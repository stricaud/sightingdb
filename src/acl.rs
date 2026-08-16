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
    /// Reaches the admin interface. Not scoped by prefix: it is about the
    /// server, not about a subtree of data.
    pub admin: bool,
}

impl Grant {
    /// Unrestricted read and write over every namespace.
    pub fn all_data() -> Self {
        Grant {
            prefix: String::new(),
            read: true,
            write: true,
            admin: false,
        }
    }

    /// The admin grant. Always its own grant, never combined with r/w in one
    /// clause: it is not scoped by namespace, and keeping it separate is what
    /// lets a key render back as `rw, admin` instead of losing half of itself.
    pub fn admin() -> Self {
        Grant {
            prefix: String::new(),
            read: false,
            write: false,
            admin: true,
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

impl Grant {
    /// Render back to the `[acl]` syntax, so a grant read from a file survives
    /// a round trip through the management interface.
    pub fn to_spec(&self) -> String {
        if self.admin {
            return "admin".to_string();
        }
        let letters = match (self.read, self.write) {
            (true, true) => "rw",
            (true, false) => "r",
            (false, true) => "w",
            (false, false) => return String::new(),
        };
        if self.prefix.is_empty() {
            letters.to_string()
        } else {
            format!("{letters}:{}", self.prefix)
        }
    }
}

/// Characters that would corrupt the file if they appeared in a key name.
///
/// A key is written as `<key> = <grants>`, so anything that could end the key,
/// start a new entry or open a section has to be refused up front rather than
/// silently producing a file that reads back as something else.
pub fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        bail!("an API key cannot be empty");
    }
    if key.len() > 256 {
        bail!("an API key cannot be longer than 256 characters");
    }
    if let Some(bad) = key.chars().find(|c| {
        c.is_whitespace()
            || matches!(
                c,
                '=' | ':' | ',' | '[' | ']' | ';' | '#' | '\\' | '"' | '\''
            )
    }) {
        bail!("an API key cannot contain {bad:?}");
    }
    Ok(())
}

/// Namespaces are written after a `:` in a grant, so the same reasoning applies.
pub fn validate_namespace(namespace: &str) -> Result<()> {
    if namespace.len() > 512 {
        bail!("a namespace cannot be longer than 512 characters");
    }
    if let Some(bad) = namespace
        .chars()
        .find(|c| c.is_whitespace() || matches!(c, '=' | ':' | ',' | '[' | ']' | ';' | '#'))
    {
        bail!("a namespace cannot contain {bad:?}");
    }
    if namespace.starts_with('_') {
        bail!("'{namespace}' is an internal namespace and cannot be granted");
    }
    Ok(())
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
        self.keys
            .insert(key.to_string(), vec![Grant::all_data(), Grant::admin()]);
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

    /// Every key with its grants, sorted, for the management interface.
    pub fn entries(&self) -> Vec<(String, Vec<Grant>)> {
        let mut entries: Vec<(String, Vec<Grant>)> = self
            .keys
            .iter()
            .map(|(key, grants)| (key.clone(), grants.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    pub fn contains(&self, key: &str) -> bool {
        self.keys.contains_key(key)
    }

    /// How many keys still hold an admin grant. Used to refuse a change that
    /// would lock everyone out.
    pub fn admin_count(&self) -> usize {
        self.keys
            .values()
            .filter(|grants| grants.iter().any(|g| g.admin))
            .count()
    }

    /// Render the whole ACL as an `[acl]` table.
    ///
    /// Keys are always quoted: an unquoted key containing a dot would become a
    /// nested table and read back as something else entirely. `validate_key`
    /// refuses quotes and backslashes, so quoting alone is sufficient here.
    pub fn to_toml(&self) -> String {
        let mut out = String::from(
            "# Written by the SightingDB management interface. Comments added\n\
             # here are replaced the next time a key is saved.\n\
             #\n\
             # \"<apikey>\" = \"<grant>[, <grant>...]\"\n\
             # grant: r | w | rw [:<namespace>]  |  admin\n\
             \n[acl]\n",
        );
        for (key, grants) in self.entries() {
            let specs: Vec<String> = grants
                .iter()
                .map(Grant::to_spec)
                .filter(|s| !s.is_empty())
                .collect();
            if specs.is_empty() {
                continue;
            }
            out.push_str(&format!("\"{key}\" = \"{}\"\n", specs.join(", ")));
        }
        out
    }

    pub fn can_read(&self, key: &str, namespace: &str) -> bool {
        self.allows(key, namespace, |grant| grant.read)
    }

    pub fn can_write(&self, key: &str, namespace: &str) -> bool {
        self.allows(key, namespace, |grant| grant.write)
    }

    /// Whether this key may use the admin interface.
    pub fn is_admin(&self, key: &str) -> bool {
        self.keys
            .get(key)
            .is_some_and(|grants| grants.iter().any(|grant| grant.admin))
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
/// admin-key = rw, admin
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

        // `admin` is its own grant rather than a letter: it is not scoped by
        // namespace and does not combine with r/w in the same clause.
        if permissions == "admin" {
            grants.push(Grant::admin());
            continue;
        }

        let (read, write) = match permissions {
            "r" => (true, false),
            "w" => (false, true),
            "rw" | "wr" => (true, true),
            other => bail!("unknown permission '{other}', expected one of r, w, rw, admin"),
        };

        grants.push(Grant {
            prefix: prefix.to_string(),
            read,
            write,
            admin: false,
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
                write: true,
                admin: false
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
                write: false,
                admin: false
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
        let err = parse_grants("superuser").unwrap_err().to_string();
        assert!(err.contains("unknown permission 'superuser'"), "{err}");
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

    // -- admin -------------------------------------------------------------

    #[test]
    fn admin_is_a_grant_of_its_own() {
        let acl = acl("k", "rw, admin");

        assert!(acl.is_admin("k"));
        assert!(acl.can_write("k", "anything"));
    }

    #[test]
    fn ordinary_keys_are_not_admins() {
        assert!(!acl("k", "rw").is_admin("k"));
        assert!(!acl("k", "r:public").is_admin("k"));
        assert!(!Acl::new().is_admin("k"));
    }

    /// The default and legacy paths call `grant_full`, which is what makes
    /// `changeme` an admin on a fresh install.
    #[test]
    fn a_full_grant_includes_admin_and_data_access() {
        let mut acl = Acl::new();
        acl.grant_full("changeme");

        assert!(acl.is_admin("changeme"));
        assert!(acl.can_read("changeme", "anything"));
        assert!(acl.can_write("changeme", "anything"));
    }

    /// Regression: admin and rw used to be one grant, which rendered as bare
    /// `admin` and silently dropped read/write when the file was written.
    #[test]
    fn a_full_grant_survives_being_written_out() {
        let mut acl = Acl::new();
        acl.grant_full("changeme");

        let specs: Vec<String> = acl.entries()[0].1.iter().map(Grant::to_spec).collect();
        assert_eq!(specs, ["rw", "admin"]);
    }

    #[test]
    fn an_admin_grant_alone_carries_no_data_access() {
        let acl = acl("k", "admin");

        assert!(acl.is_admin("k"));
        assert!(!acl.can_read("k", "anything"));
        assert!(!acl.can_write("k", "anything"));
    }

    // -- writing back ------------------------------------------------------

    #[test]
    fn grants_round_trip_through_their_spec() {
        for spec in ["rw", "r", "w", "rw:feeds/misp", "r:public", "admin"] {
            let parsed = parse_grants(spec).unwrap();
            assert_eq!(parsed[0].to_spec(), spec, "{spec}");
            // And parsing the rendering gives the same grant back.
            assert_eq!(
                parse_grants(&parsed[0].to_spec()).unwrap(),
                parsed,
                "{spec}"
            );
        }
    }

    #[test]
    fn an_acl_round_trips_through_the_toml_form() {
        let mut acl = Acl::new();
        acl.grant_full("changeme");
        acl.set("feed", parse_grants("rw:feeds/misp").unwrap());
        acl.set("mixed", parse_grants("r:public, w:inbox, admin").unwrap());

        let rendered = acl.to_toml();
        #[derive(serde::Deserialize)]
        struct AclFile {
            acl: std::collections::HashMap<String, String>,
        }
        let parsed: AclFile = toml::from_str(&rendered).unwrap();

        let mut restored = Acl::new();
        for (key, spec) in parsed.acl {
            restored.set(&key, parse_grants(&spec).unwrap());
        }

        assert_eq!(restored, acl, "rendered as:\n{rendered}");
    }

    #[test]
    fn the_written_file_carries_a_warning_that_it_is_generated() {
        let mut acl = Acl::new();
        acl.grant_full("k");
        assert!(acl.to_toml().contains("management interface"));
    }

    /// An unquoted dotted key would become a nested table and read back wrong.
    #[test]
    fn a_dotted_key_survives_being_written_out() {
        let mut acl = Acl::new();
        acl.grant_full("feed.misp");

        #[derive(serde::Deserialize)]
        struct AclFile {
            acl: std::collections::HashMap<String, String>,
        }
        let parsed: AclFile = toml::from_str(&acl.to_toml()).unwrap();

        assert_eq!(parsed.acl.keys().collect::<Vec<_>>(), ["feed.misp"]);
    }

    #[test]
    fn entries_come_back_sorted() {
        let mut acl = Acl::new();
        for key in ["zed", "alice", "mallory"] {
            acl.grant_full(key);
        }
        let names: Vec<String> = acl.entries().into_iter().map(|(k, _)| k).collect();
        assert_eq!(names, ["alice", "mallory", "zed"]);
    }

    #[test]
    fn admins_are_counted() {
        let mut acl = Acl::new();
        acl.grant_full("a");
        acl.set("b", parse_grants("rw").unwrap());
        acl.set("c", parse_grants("admin").unwrap());

        assert_eq!(acl.admin_count(), 2);
    }

    // -- validation --------------------------------------------------------

    /// A key carrying `=` or a newline would write a file that reads back as
    /// something else entirely, so these are refused before they are stored.
    #[test]
    fn keys_that_would_corrupt_the_file_are_refused() {
        for bad in [
            "",
            "has space",
            "has=equals",
            "has:colon",
            "has,comma",
            "has[bracket",
            "has#hash",
            "has;semi",
            "has\nnewline",
            "has\ttab",
        ] {
            assert!(
                validate_key(bad).is_err(),
                "{bad:?} should have been refused"
            );
        }
    }

    #[test]
    fn ordinary_keys_are_accepted() {
        for good in ["changeme", "feed-misp", "a.b_c", "Ab3-x", &"k".repeat(256)] {
            assert!(
                validate_key(good).is_ok(),
                "{good:?} should have been accepted"
            );
        }
        assert!(validate_key(&"k".repeat(257)).is_err());
    }

    #[test]
    fn namespaces_are_validated_too() {
        assert!(validate_namespace("feeds/misp").is_ok());
        assert!(
            validate_namespace("").is_ok(),
            "an empty prefix means everything"
        );
        assert!(validate_namespace("has space").is_err());
        assert!(validate_namespace("has:colon").is_err());
        // Granting the internal trees would hand out API keys or search history.
        assert!(validate_namespace("_config/acl").is_err());
        assert!(validate_namespace("_shadow/x").is_err());
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
