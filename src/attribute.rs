use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;
use anyhow::Result;

use chrono::serde::ts_seconds;
use std::collections::BTreeMap;
use serde::ser::SerializeStruct;

#[derive(Deserialize, Clone, PartialEq)]
pub struct Attribute {
    pub value: String,
    #[serde(with = "ts_seconds")]
    pub first_seen: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub last_seen: DateTime<Utc>,
    pub count: u128,
    pub tags: String,
    pub ttl: u128,
    pub stats: BTreeMap<i64, u128>,
    // i64 because DateTime.timestamp() returns i64 :'(; We track count by time.
    pub consensus: u128,
}

//"stats":{"1586548800":1},

impl Attribute {
    pub fn new(value: &str) -> Attribute {
        Attribute {
            value: String::from(value), // FIXME: change to Vec<u8>
            first_seen: DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc),
            last_seen: DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc),
            count: 0,
            tags: String::from(""),
            ttl: 0,
            stats: BTreeMap::new(),
            consensus: 0,
        }
    }

    pub fn make_stats(&mut self, time: DateTime<Utc>) {
        let rounded_time = time.timestamp() - time.timestamp() % 3600;
        self.stats
            .entry(rounded_time)
            .and_modify(|e| *e += 1)
            .or_insert(1);
    }

    pub fn make_stats_from_timestamp(&mut self, timestamp: i64) {
        let rounded_time = timestamp - timestamp % 3600;
        self.stats
            .entry(rounded_time)
            .and_modify(|e| *e += 1)
            .or_insert(1);
    }

    pub fn count(&mut self) -> u128 {
        self.count
    }

    pub fn incr(&mut self) {
        if self.first_seen.timestamp() == 0 {
            self.first_seen = Utc::now();
        }
        self.last_seen = Utc::now();

        self.make_stats(self.last_seen);

        self.count += 1;
    }

    pub fn set_consensus(&mut self, consensus_count: u128) {
        self.consensus = consensus_count;
    }

    pub fn incr_from_timestamp(&mut self, timestamp: i64) {
        if self.first_seen.timestamp() == 0 {
            self.first_seen =
                DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), Utc);
        }
        if timestamp < self.first_seen.timestamp() {
            self.first_seen =
                DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), Utc);
        }
        if timestamp > self.last_seen.timestamp() {
            self.last_seen =
                DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), Utc);
        }
        self.make_stats_from_timestamp(timestamp);
        self.count += 1;
    }

    pub fn increment(&mut self, timestamp: i64) {
        if timestamp.is_negative() {
            self.incr()
        } else {
            self.incr_from_timestamp(timestamp)
        }
    }

    pub fn serialize_with_stats(&self) -> Result<String> {
        let mut json_value = serde_json::to_value(&self)?;
        json_value["stats"] = serde_json::to_value(&self.stats)?;
        serde_json::to_string(&json_value).map_err(|e| e.into())
    }
}

impl fmt::Debug for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Attribute {{ value: {}, first_seen: {:?}, last_seen: {:?}, count: {}, tags: {:?}, ttl: {:?}}}",
               self.value, self.first_seen, self.last_seen, self.count, self.tags, self.ttl)
    }
}

impl Serialize for Attribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer ,
    {

        let mut state = serializer.serialize_struct("Attribute", 7)?;
        state.serialize_field("value", &self.value)?;
        // Following code from Serialize impl in to_seconds
        state.serialize_field("first_seen", &self.first_seen.timestamp())?;
        state.serialize_field("last_seen", &self.last_seen.timestamp())?;
        state.serialize_field("count", &self.count)?;
        state.serialize_field("tags", &self.tags)?;
        state.serialize_field("ttl", &self.ttl)?;
        state.serialize_field("consensus", &self.consensus)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_with_stats() -> Result<()> {
        let mut stats: BTreeMap<i64, u128> = BTreeMap::new();
        for i in 0..5 {
            stats.insert(i, i as u128);
        }
        let mut attr = Attribute::new("test");
        attr.stats = stats;
        let serialized = &attr.serialize_with_stats()?;
        let deserialized: Attribute = serde_json::from_str(&serialized)?;
        assert_eq!(deserialized, attr);
        Ok(())
    }
}