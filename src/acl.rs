use std::collections::HashMap;

use anyhow::{Result, bail};

/// One permission an API key holds over a subtree of the namespace hierarchy.
///
/// An empty `prefix` covers every namespace, which is what "full access" means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub prefix: String,
    pub read: bool,
    pub write: bool,
}

impl Grant {
    pub fn full() -> Self {
        Grant {
            prefix: String::new(),
            read: true,
            write: true,
        }
    }

    /// Whether this grant's prefix covers `namespace`.
    ///
    /// Matching is per path segment, so a grant on `feeds/misp` covers
    /// `feeds/misp/ips` but *not* `feeds/misp-internal`. Leading and trailing
    /// slashes are ignored on both sides, since callers reach namespaces
    /// through URLs and are inconsistent about them.
    fn covers(&self, namespace: &str) -> bool {
        let mut actual = segments(namespace);
        for wanted in segments(&self.prefix) {
            match actual.next() {
                Some(segment) if segment == wanted => {}
                _ => return false,
            }
        }
        true
    }
}

fn segments(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|segment| !segment.is_empty())
}

/// Which API keys exist and what each may do.
///
/// Access is allow-only: a key is denied unless one of its grants both covers
/// the namespace and carries the permission being asked for. A key that is not
/// present at all is denied outright.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Acl {
    keys: HashMap<String, Vec<Grant>>,
}

impl Acl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Give `key` unrestricted access, replacing any grants it had.
    pub fn grant_full(&mut self, key: &str) {
        self.keys.insert(key.to_string(), vec![Grant::full()]);
    }

    pub fn set(&mut self, key: &str, grants: Vec<Grant>) {
        self.keys.insert(key.to_string(), grants);
    }

    pub fn remove(&mut self, key: &str) -> bool {
        self.keys.remove(key).is_some()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn can_read(&self, key: &str, namespace: &str) -> bool {
        self.allows(key, namespace, |grant| grant.read)
    }

    pub fn can_write(&self, key: &str, namespace: &str) -> bool {
        self.allows(key, namespace, |grant| grant.write)
    }

    fn allows(&self, key: &str, namespace: &str, permitted: impl Fn(&Grant) -> bool) -> bool {
        let Some(grants) = self.keys.get(key) else {
            return false;
        };
        grants
            .iter()
            .any(|grant| permitted(grant) && grant.covers(namespace))
    }
}

/// Parse the right-hand side of an `[acl]` entry.
///
/// The syntax is a comma-separated list of `r`, `w` or `rw`, each optionally
/// followed by `:<namespace prefix>`. Without a prefix the grant is global:
///
/// ```text
/// analyst   = r
/// feed-misp = rw:feeds/misp
/// mixed     = r, w:staging
/// ```
pub fn parse_grants(spec: &str) -> Result<Vec<Grant>> {
    let mut grants = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let (permissions, prefix) = match part.split_once(':') {
            Some((permissions, prefix)) => (permissions.trim(), prefix.trim()),
            None => (part, ""),
        };

        let (read, write) = match permissions {
            "r" => (true, false),
            "w" => (false, true),
            "rw" | "wr" => (true, true),
            other => bail!("unknown permission '{other}', expected one of r, w, rw"),
        };

        grants.push(Grant {
            prefix: prefix.to_string(),
            read,
            write,
        });
    }

    if grants.is_empty() {
        bail!("no grants given; use 'r', 'w' or 'rw', optionally as 'rw:<namespace>'");
    }

    Ok(grants)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(key: &str, spec: &str) -> Acl {
        let mut acl = Acl::new();
        acl.set(key, parse_grants(spec).unwrap());
        acl
    }

    // -- parsing -----------------------------------------------------------

    #[test]
    fn a_bare_permission_is_global() {
        assert_eq!(
            parse_grants("rw").unwrap(),
            vec![Grant {
                prefix: String::new(),
                read: true,
                write: true
            }]
        );
    }

    #[test]
    fn permissions_can_be_scoped_to_a_prefix() {
        assert_eq!(
            parse_grants("r:feeds/misp").unwrap(),
            vec![Grant {
                prefix: "feeds/misp".to_string(),
                read: true,
                write: false
            }]
        );
    }

    #[test]
    fn several_grants_can_be_listed() {
        let grants = parse_grants(" r , w:staging ,rw:feeds/misp ").unwrap();

        assert_eq!(grants.len(), 3);
        assert!(grants[0].read && !grants[0].write && grants[0].prefix.is_empty());
        assert!(!grants[1].read && grants[1].write && grants[1].prefix == "staging");
        assert!(grants[2].read && grants[2].write);
    }

    #[test]
    fn rw_and_wr_mean_the_same_thing() {
        assert_eq!(parse_grants("rw").unwrap(), parse_grants("wr").unwrap());
    }

    #[test]
    fn an_unknown_permission_is_an_error() {
        let err = parse_grants("admin").unwrap_err().to_string();
        assert!(err.contains("unknown permission 'admin'"), "{err}");
    }

    #[test]
    fn an_empty_spec_is_an_error() {
        assert!(parse_grants("   ").is_err());
        assert!(parse_grants(",,").is_err());
    }

    // -- matching ----------------------------------------------------------

    #[test]
    fn a_global_grant_covers_every_namespace() {
        let acl = acl("k", "rw");

        assert!(acl.can_read("k", "anything/at/all"));
        assert!(acl.can_write("k", ""));
    }

    #[test]
    fn a_scoped_grant_covers_its_own_subtree() {
        let acl = acl("k", "rw:feeds/misp");

        assert!(acl.can_read("k", "feeds/misp"));
        assert!(acl.can_read("k", "feeds/misp/ips"));
        assert!(acl.can_write("k", "feeds/misp/ips/v4"));
    }

    /// The whole point of matching per segment: a prefix must not leak into a
    /// sibling namespace that merely starts with the same characters.
    #[test]
    fn a_scoped_grant_does_not_leak_into_similarly_named_siblings() {
        let acl = acl("k", "rw:feeds/misp");

        assert!(!acl.can_read("k", "feeds/misp-internal"));
        assert!(!acl.can_read("k", "feeds/misperfect/data"));
        assert!(!acl.can_write("k", "feeds"));
        assert!(!acl.can_read("k", "other/feeds/misp"));
    }

    #[test]
    fn surrounding_slashes_do_not_matter() {
        let acl = acl("k", "rw:/feeds/misp/");

        assert!(acl.can_read("k", "feeds/misp"));
        assert!(acl.can_read("k", "/feeds/misp/"));
        assert!(acl.can_read("k", "feeds/misp/ips/"));
    }

    #[test]
    fn read_and_write_are_separate() {
        let acl = acl("k", "r:public, w:inbox");

        assert!(acl.can_read("k", "public/data"));
        assert!(!acl.can_write("k", "public/data"));

        assert!(acl.can_write("k", "inbox/data"));
        assert!(!acl.can_read("k", "inbox/data"));
    }

    #[test]
    fn grants_are_unioned() {
        let acl = acl("k", "r:a, w:a");

        assert!(acl.can_read("k", "a/x"));
        assert!(acl.can_write("k", "a/x"));
    }

    #[test]
    fn an_unknown_key_is_denied_everything() {
        let acl = acl("k", "rw");

        assert!(!acl.can_read("other", "anything"));
        assert!(!acl.can_write("other", "anything"));
        assert!(!acl.can_read("", "anything"));
    }

    #[test]
    fn a_key_with_no_matching_grant_is_denied() {
        let acl = acl("k", "rw:feeds");

        assert!(!acl.can_read("k", "secrets"));
    }

    #[test]
    fn keys_are_case_sensitive() {
        let acl = acl("SeCret", "rw");

        assert!(acl.can_read("SeCret", "ns"));
        assert!(!acl.can_read("secret", "ns"));
    }

    // -- management --------------------------------------------------------

    #[test]
    fn an_empty_acl_denies_everyone() {
        let acl = Acl::new();

        assert!(acl.is_empty());
        assert!(!acl.can_read("anything", "anywhere"));
    }

    #[test]
    fn grant_full_replaces_existing_grants() {
        let mut acl = acl("k", "r:narrow");
        acl.grant_full("k");

        assert!(acl.can_write("k", "anywhere"));
        assert_eq!(acl.len(), 1);
    }

    #[test]
    fn removing_a_key_revokes_it() {
        let mut acl = acl("k", "rw");

        assert!(acl.remove("k"));
        assert!(!acl.remove("k"));
        assert!(!acl.can_read("k", "ns"));
    }
}
