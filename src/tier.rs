//! How long a shard stays in memory once it has been touched.
//!
//! The three tiers are one mechanism with different idle windows rather than
//! three implementations. That matters for `cold`: taken literally, "always on
//! disk" would mean loading, mutating and re-saving a shard for every single
//! write, so a thousand-item bulk POST into one namespace would become a
//! thousand decompress/compress cycles. Instead a cold shard is loaded on
//! demand and dropped at the next sweep, so a burst of activity costs one load
//! rather than one per operation.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Never evicted.
    Hot,
    /// Evicted once untouched for the configured window.
    Warm,
    /// Evicted at the next sweep after it falls idle.
    Cold,
}

impl Tier {
    pub fn parse(raw: &str) -> Result<Tier> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "hot" => Ok(Tier::Hot),
            "warm" => Ok(Tier::Warm),
            "cold" => Ok(Tier::Cold),
            other => bail!("unknown tier '{other}', expected hot, warm or cold"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Hot => "hot",
            Tier::Warm => "warm",
            Tier::Cold => "cold",
        }
    }
}

/// One shard's storage settings. Either half may be left unset, in which case
/// the configured default applies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    /// Seconds a warm shard may sit untouched. `None` takes the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warm_idle: Option<u64>,
}

impl Entry {
    /// A tier with no idle window of its own.
    #[cfg(test)]
    pub fn tier(tier: Tier) -> Entry {
        Entry {
            tier: Some(tier),
            warm_idle: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.tier.is_none() && self.warm_idle.is_none()
    }
}

/// What a shard's settings work out to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Resolved {
    pub tier: Tier,
    pub warm_idle: u64,
    /// Set on the shard itself; absent means it takes the configured default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub own_tier: Option<Tier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub own_warm_idle: Option<u64>,
}

impl Resolved {
    /// How long this shard may sit untouched, or `None` if it never goes.
    pub fn idle_allowance(&self) -> Option<Duration> {
        match self.tier {
            Tier::Hot => None,
            Tier::Warm => Some(Duration::from_secs(self.warm_idle)),
            Tier::Cold => Some(Duration::ZERO),
        }
    }
}

/// Which tier each shard is in, and how long `warm` waits for it.
///
/// Keyed by shard — the first path segment of a namespace — because a shard is
/// one file, paged in and out as a unit. Setting one therefore covers every
/// namespace under it, `feeds` covering `feeds/misp/ips` and its siblings
/// alike; there is no finer setting because there is no finer eviction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierPolicy {
    pub default_tier: Tier,
    /// Keyed by shard. An entry may set the tier, the idle window, or both.
    pub entries: HashMap<String, Entry>,
    /// The idle window a warm shard gets when it does not name its own.
    pub warm_idle: Duration,
}

impl Default for TierPolicy {
    fn default() -> Self {
        Self {
            // Everything resident unless asked otherwise, which is how the
            // database behaved before tiering existed.
            default_tier: Tier::Hot,
            entries: HashMap::new(),
            warm_idle: Duration::from_secs(3600),
        }
    }
}

impl TierPolicy {
    /// The settings in force for a shard, and whether each half is the shard's
    /// own or the configured default.
    pub fn resolve(&self, shard: &str) -> Resolved {
        // Consensus is consulted on every write and API keys on every request,
        // so internal state is never a candidate for eviction whatever the
        // configuration says.
        if shard == crate::persistence::INTERNAL_SHARD {
            return Resolved {
                tier: Tier::Hot,
                warm_idle: self.warm_idle.as_secs(),
                own_tier: None,
                own_warm_idle: None,
            };
        }

        let entry = self.entry(shard);
        Resolved {
            tier: entry.tier.unwrap_or(self.default_tier),
            warm_idle: entry.warm_idle.unwrap_or(self.warm_idle.as_secs()),
            own_tier: entry.tier,
            own_warm_idle: entry.warm_idle,
        }
    }

    #[cfg(test)]
    pub fn tier_of(&self, shard: &str) -> Tier {
        self.resolve(shard).tier
    }

    /// Seconds a shard may sit untouched before it is evicted, or `None` if it
    /// never is.
    pub fn idle_allowance(&self, shard: &str) -> Option<Duration> {
        self.resolve(shard).idle_allowance()
    }

    /// Set or clear one shard's settings. An empty entry is a removal, so the
    /// shard goes back to the configured defaults.
    pub fn set(&mut self, shard: &str, entry: Entry) {
        let shard = shard.trim().trim_matches('/').to_string();
        if entry.is_empty() {
            self.entries.remove(&shard);
        } else {
            self.entries.insert(shard, entry);
        }
    }

    pub fn entry(&self, shard: &str) -> Entry {
        self.entries
            .get(shard.trim().trim_matches('/'))
            .copied()
            .unwrap_or_default()
    }
}

/// The on-disk form, written by the management interface.
///
/// Kept in its own file for the same reason API keys are: it is rewritten by
/// the program, and rewriting the hand-maintained configuration would discard
/// its comments.
#[derive(Debug, Serialize, Deserialize)]
pub struct TierFile {
    pub default_tier: String,
    pub warm_idle: u64,
    #[serde(default)]
    pub tiers: HashMap<String, toml::Value>,
}

/// Read one entry of the `[tiers]` table.
///
/// Either spelling works, because the short one is what almost every entry
/// wants and the long one is what a per-namespace idle window needs:
///
/// ```toml
/// "archive" = "cold"
/// "feeds" = { tier = "warm", warm_idle = 86400 }
/// "staging" = { warm_idle = 300 }
/// ```
pub fn parse_entry(value: &toml::Value) -> Result<Entry> {
    match value {
        toml::Value::String(tier) => Ok(Entry {
            tier: Some(Tier::parse(tier)?),
            warm_idle: None,
        }),
        toml::Value::Table(table) => {
            let mut entry = Entry::default();
            for (key, field) in table {
                match key.as_str() {
                    "tier" => {
                        let tier = field.as_str().with_context(|| {
                            format!("'tier' should be a string, found {}", field.type_str())
                        })?;
                        entry.tier = Some(Tier::parse(tier)?);
                    }
                    "warm_idle" => {
                        let seconds = field
                            .as_integer()
                            .filter(|seconds| *seconds >= 0)
                            .with_context(|| {
                                format!("'warm_idle' should be a number of seconds, found {field}")
                            })?;
                        entry.warm_idle = Some(seconds as u64);
                    }
                    other => bail!("unknown key '{other}', expected tier or warm_idle"),
                }
            }
            if entry.is_empty() {
                bail!("says nothing: give it a tier, a warm_idle, or both");
            }
            Ok(entry)
        }
        other => bail!(
            "should be a tier, or a table of tier and warm_idle, found {}",
            other.type_str()
        ),
    }
}

impl TierPolicy {
    pub fn load(path: &Path) -> Result<TierPolicy> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file: TierFile =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

        let mut entries = HashMap::new();
        for (namespace, value) in file.tiers {
            let entry = parse_entry(&value)
                .with_context(|| format!("for '{namespace}' in {}", path.display()))?;
            entries.insert(namespace, entry);
        }

        Ok(TierPolicy {
            default_tier: Tier::parse(&file.default_tier)
                .with_context(|| format!("for 'default_tier' in {}", path.display()))?,
            entries,
            warm_idle: Duration::from_secs(file.warm_idle),
        })
    }

    /// Write atomically, so a crash mid-write cannot leave a file that fails to
    /// parse and takes the next startup with it.
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut body = String::from(
            "# Written by the SightingDB management interface. Comments added here\n\
             # are replaced the next time a tier is changed.\n\
             #\n\
             # hot   never evicted\n\
             # warm  dropped once untouched for warm_idle seconds\n\
             # cold  dropped at the next sweep once idle\n\
             #\n\
             # Keyed by the top-level namespace, which is the unit that is paged in\n\
             # and out: \"feeds\" covers \"feeds/misp/ips\" and everything beside it.\n\
             # An entry may set the tier, the idle window, or both.\n\n",
        );
        body.push_str(&format!(
            "default_tier = \"{}\"\n",
            self.default_tier.as_str()
        ));
        body.push_str(&format!(
            "warm_idle = {}\n\n[tiers]\n",
            self.warm_idle.as_secs()
        ));

        let mut entries: Vec<(&String, &Entry)> = self.entries.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for (namespace, entry) in entries {
            let value = match (entry.tier, entry.warm_idle) {
                (Some(tier), None) => format!("\"{}\"", tier.as_str()),
                (Some(tier), Some(idle)) => {
                    format!("{{ tier = \"{}\", warm_idle = {idle} }}", tier.as_str())
                }
                (None, Some(idle)) => format!("{{ warm_idle = {idle} }}"),
                // Not stored: `set` removes an entry that says nothing.
                (None, None) => continue,
            };
            body.push_str(&format!("\"{namespace}\" = {value}\n"));
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let temp = path.with_extension("tmp");
        std::fs::write(&temp, body).with_context(|| format!("writing {}", temp.display()))?;
        std::fs::rename(&temp, path)
            .with_context(|| format!("renaming {} to {}", temp.display(), path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> TierPolicy {
        TierPolicy {
            default_tier: Tier::Warm,
            entries: HashMap::from([
                ("myorg".to_string(), Entry::tier(Tier::Hot)),
                ("archive".to_string(), Entry::tier(Tier::Cold)),
            ]),
            warm_idle: Duration::from_secs(3600),
        }
    }

    #[test]
    fn tiers_parse_from_configuration() {
        assert_eq!(Tier::parse("hot").unwrap(), Tier::Hot);
        assert_eq!(Tier::parse(" Warm ").unwrap(), Tier::Warm);
        assert_eq!(Tier::parse("COLD").unwrap(), Tier::Cold);
        assert!(Tier::parse("lukewarm").is_err());
    }

    #[test]
    fn a_shard_takes_its_configured_tier() {
        let p = policy();
        assert_eq!(p.tier_of("myorg"), Tier::Hot);
        assert_eq!(p.tier_of("archive"), Tier::Cold);
        assert_eq!(p.tier_of("anything-else"), Tier::Warm);
    }

    /// Every write consults `_all` and every request the API keys, so evicting
    /// the internal shard would mean loading it back constantly.
    #[test]
    fn the_internal_shard_is_always_hot() {
        let mut p = policy();
        p.default_tier = Tier::Cold;
        p.set(crate::persistence::INTERNAL_SHARD, Entry::tier(Tier::Cold));

        assert_eq!(p.tier_of(crate::persistence::INTERNAL_SHARD), Tier::Hot);
        assert_eq!(p.idle_allowance(crate::persistence::INTERNAL_SHARD), None);
    }

    #[test]
    fn a_shard_may_set_its_own_idle_window() {
        let mut p = policy();
        assert_eq!(p.resolve("other").warm_idle, 3600);
        assert_eq!(p.idle_allowance("other"), Some(Duration::from_secs(3600)));

        // Warm, but this one is worth keeping for a day.
        p.set(
            "other",
            Entry {
                tier: Some(Tier::Warm),
                warm_idle: Some(86_400),
            },
        );
        assert_eq!(p.idle_allowance("other"), Some(Duration::from_secs(86_400)));

        // The window alone, leaving the tier to the default.
        p.set(
            "windowed",
            Entry {
                tier: None,
                warm_idle: Some(60),
            },
        );
        let resolved = p.resolve("windowed");
        assert_eq!(resolved.tier, Tier::Warm, "the default tier still applies");
        assert_eq!(resolved.warm_idle, 60);
        assert_eq!(resolved.own_tier, None);
        assert_eq!(resolved.own_warm_idle, Some(60));

        // A window is only a window: a hot shard never goes, and a cold one
        // goes at the next sweep whatever it says.
        p.set(
            "myorg",
            Entry {
                tier: Some(Tier::Hot),
                warm_idle: Some(60),
            },
        );
        assert_eq!(p.idle_allowance("myorg"), None);
        p.set(
            "archive",
            Entry {
                tier: Some(Tier::Cold),
                warm_idle: Some(60),
            },
        );
        assert_eq!(p.idle_allowance("archive"), Some(Duration::ZERO));
    }

    #[test]
    fn clearing_a_shard_puts_it_back_on_the_defaults() {
        let mut p = policy();
        assert_eq!(p.resolve("myorg").own_tier, Some(Tier::Hot));

        p.set("myorg", Entry::default());

        let resolved = p.resolve("myorg");
        assert_eq!(resolved.tier, Tier::Warm, "the default");
        assert_eq!(resolved.own_tier, None);
        assert!(!p.entries.contains_key("myorg"));
    }

    #[test]
    fn an_idle_window_survives_the_file() {
        let dir = std::env::temp_dir().join("sightingdb-tierfile-idle");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tiers.toml");

        let mut original = policy();
        original.set(
            "feeds",
            Entry {
                tier: Some(Tier::Warm),
                warm_idle: Some(86_400),
            },
        );
        original.set(
            "staging",
            Entry {
                tier: None,
                warm_idle: Some(300),
            },
        );
        original.save(&path).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains(r#""feeds" = { tier = "warm", warm_idle = 86400 }"#),
            "{written}"
        );
        assert!(
            written.contains(r#""staging" = { warm_idle = 300 }"#),
            "{written}"
        );
        // The short spelling is kept for entries that only set a tier.
        assert!(written.contains(r#""archive" = "cold""#), "{written}");

        assert_eq!(TierPolicy::load(&path).unwrap(), original);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_nonsense_entry_in_the_file_says_what_is_wrong() {
        let dir = std::env::temp_dir().join("sightingdb-tierfile-nonsense");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tiers.toml");

        for (entry, expected) in [
            (
                "feeds = { tier = \"warm\", idle = 60 }",
                "unknown key 'idle'",
            ),
            ("feeds = { warm_idle = -5 }", "warm_idle"),
            ("feeds = {}", "says nothing"),
            ("feeds = 60", "should be a tier"),
        ] {
            std::fs::write(
                &path,
                format!("default_tier = \"hot\"\nwarm_idle = 60\n\n[tiers]\n{entry}\n"),
            )
            .unwrap();
            let err = format!("{:#}", TierPolicy::load(&path).unwrap_err());
            assert!(err.contains(expected), "{entry} gave {err}");
            assert!(err.contains("feeds"), "{entry} gave {err}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_policy_round_trips_through_its_file() {
        let dir = std::env::temp_dir().join("sightingdb-tierfile");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tiers.toml");

        let original = policy();
        original.save(&path).unwrap();
        let restored = TierPolicy::load(&path).unwrap();

        assert_eq!(restored, original);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_written_file_says_it_is_generated() {
        let dir = std::env::temp_dir().join("sightingdb-tierfile-doc");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tiers.toml");

        policy().save(&path).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();

        assert!(body.contains("management interface"), "{body}");
        // Quoted, so a shard name containing a dot cannot become a sub-table.
        assert!(body.contains("\"myorg\" = \"hot\""), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bad_tier_in_the_file_names_the_shard() {
        let dir = std::env::temp_dir().join("sightingdb-tierfile-bad");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tiers.toml");
        std::fs::write(
            &path,
            "default_tier = \"hot\"\nwarm_idle = 60\n\n[tiers]\nmyorg = \"tepid\"\n",
        )
        .unwrap();

        let err = format!("{:#}", TierPolicy::load(&path).unwrap_err());
        assert!(err.contains("myorg"), "{err}");
        assert!(err.contains("tepid"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idle_allowance_follows_the_tier() {
        let p = policy();
        assert_eq!(p.idle_allowance("myorg"), None);
        assert_eq!(p.idle_allowance("other"), Some(Duration::from_secs(3600)));
        // Cold still gets to finish the burst it is in; it goes at the next sweep.
        assert_eq!(p.idle_allowance("archive"), Some(Duration::ZERO));
    }
}
