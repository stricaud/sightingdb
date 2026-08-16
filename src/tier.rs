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
use std::time::Duration;

use anyhow::{Result, bail};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

/// Which tier each shard is in, and how long `warm` waits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierPolicy {
    pub default_tier: Tier,
    /// Keyed by shard, which is the first path segment of a namespace.
    pub shards: HashMap<String, Tier>,
    pub warm_idle: Duration,
}

impl Default for TierPolicy {
    fn default() -> Self {
        Self {
            // Everything resident unless asked otherwise, which is how the
            // database behaved before tiering existed.
            default_tier: Tier::Hot,
            shards: HashMap::new(),
            warm_idle: Duration::from_secs(3600),
        }
    }
}

impl TierPolicy {
    pub fn tier_of(&self, shard: &str) -> Tier {
        // Consensus is consulted on every write and API keys on every request,
        // so the internal shard is never a candidate for eviction whatever the
        // configuration says.
        if shard == crate::persistence::INTERNAL_SHARD {
            return Tier::Hot;
        }
        self.shards.get(shard).copied().unwrap_or(self.default_tier)
    }

    /// Seconds a shard may sit untouched before it is evicted, or `None` if it
    /// never is.
    pub fn idle_allowance(&self, shard: &str) -> Option<Duration> {
        match self.tier_of(shard) {
            Tier::Hot => None,
            Tier::Warm => Some(self.warm_idle),
            Tier::Cold => Some(Duration::ZERO),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> TierPolicy {
        TierPolicy {
            default_tier: Tier::Warm,
            shards: HashMap::from([
                ("myorg".to_string(), Tier::Hot),
                ("archive".to_string(), Tier::Cold),
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
        p.shards
            .insert(crate::persistence::INTERNAL_SHARD.to_string(), Tier::Cold);

        assert_eq!(p.tier_of(crate::persistence::INTERNAL_SHARD), Tier::Hot);
        assert_eq!(p.idle_allowance(crate::persistence::INTERNAL_SHARD), None);
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
