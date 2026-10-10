//! The tag vocabulary: what a tag means, and what colour it is shown in.
//!
//! Tags themselves live on values, as a comma-separated set on each
//! [`crate::attribute::Attribute`]. This is the separate, much smaller thing
//! beside them: a description and a colour per tag, so the management
//! interface can render `tlp:red` red rather than as grey text, and can offer
//! the tags already in use while one is being typed.
//!
//! **It is deliberately not authoritative over what may be written.** A value
//! can carry a tag this vocabulary has never heard of, and that is not an
//! error — a feed brings whatever tags it brings, and refusing them would lose
//! data to make a table tidier. The vocabulary only decides presentation, and
//! an unknown tag is shown in a neutral colour and listed as unknown so it can
//! be adopted with one click.
//!
//! **Families.** A name ending in `:` is a prefix rather than a tag:
//! `stix-type:` gives a colour to `stix-type:ipv4-addr` and everything else
//! under it. This exists because half of SightingDB's own vocabulary is
//! `key:value` with an open set of values — see [`crate::stix`] — which could
//! not be enumerated here even in principle. It also matches how MISP
//! taxonomies are shaped, `namespace:predicate`, so a MISP taxonomy can be
//! given one colour by its namespace.
//!
//! **Where it lives.** Its own file, named by `tags_file`, machine-owned and
//! rewritten whole — the same split as the ACL and for the same reason: the
//! main configuration is hand-maintained and comment-rich, and a program that
//! rewrites it destroys those comments. See [`crate::acl`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The longest a tag name may be, matching what a value's tag field accepts.
const MAX_NAME: usize = 128;

/// The colour an unknown tag is shown in.
pub const UNKNOWN_COLOUR: &str = "#6b7280";

/// One tag's presentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    /// `#rgb` or `#rrggbb`.
    pub colour: String,
    #[serde(default)]
    pub description: String,
}

/// The file's shape: `[tags."tlp:red"]` tables.
#[derive(Debug, Default, Deserialize, Serialize)]
struct TagFile {
    #[serde(default)]
    tags: BTreeMap<String, Tag>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vocabulary {
    tags: BTreeMap<String, Tag>,
}

/// MISP's own TLP colours, and a colour per family of SightingDB's vocabulary.
///
/// The TLP hex values are the ones in MISP's `tlp` taxonomy rather than
/// anything chosen here, so a tag exported to MISP and back looks the same in
/// both. The rest are families — see the module note — covering the tags the
/// STIX export reads, which are the ones a user meets most.
const SEED: &[(&str, &str, &str)] = &[
    (
        "tlp:red",
        "#FF2B2B",
        "Not for disclosure, restricted to participants only.",
    ),
    (
        "tlp:amber",
        "#FFC000",
        "Limited disclosure, restricted to participants' organizations.",
    ),
    (
        "tlp:amber+strict",
        "#FFC000",
        "Limited disclosure, restricted to participants' organization only.",
    ),
    (
        "tlp:green",
        "#33FF00",
        "Limited disclosure, restricted to the community.",
    ),
    ("tlp:clear", "#FFFFFF", "Disclosure is not limited."),
    (
        "tlp:white",
        "#FFFFFF",
        "Superseded by tlp:clear; kept because feeds still send it.",
    ),
    (
        "stix-type:",
        "#7c3aed",
        "The STIX observable type this value exports as, overriding what it looks like.",
    ),
    (
        "indicator-type:",
        "#2563eb",
        "The STIX indicator type, such as malicious-activity.",
    ),
    (
        "confidence:",
        "#0891b2",
        "Confidence in the sighting, 0 to 100.",
    ),
    ("identity:", "#059669", "Who reported the sighting."),
    ("misp-type:", "#d97706", "The MISP attribute type imported."),
    (
        "misp-category:",
        "#d97706",
        "The MISP attribute category imported.",
    ),
    ("misp-event:", "#d97706", "The MISP event this came from."),
];

impl Vocabulary {
    /// The vocabulary a server starts with when no file has been written yet.
    pub fn seeded() -> Self {
        let tags = SEED
            .iter()
            .map(|(name, colour, description)| {
                (
                    (*name).to_string(),
                    Tag {
                        colour: (*colour).to_string(),
                        description: (*description).to_string(),
                    },
                )
            })
            .collect();
        Self { tags }
    }

    /// Read a vocabulary file.
    ///
    /// Entries that do not validate are dropped with a warning rather than
    /// failing the load: this file decides colours, and a server that refused
    /// to start over a malformed one would be trading something that matters
    /// for something that does not.
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        let parsed: TagFile = toml::from_str(text)?;
        let mut tags = BTreeMap::new();
        for (name, tag) in parsed.tags {
            match validate(&name, &tag.colour) {
                Ok(()) => {
                    tags.insert(name, tag);
                }
                Err(e) => log::warn!("Ignoring tag '{name}' in the tag vocabulary: {e}"),
            }
        }
        Ok(Self { tags })
    }

    pub fn to_toml(&self) -> String {
        let mut out = String::from(
            "# Written by the SightingDB management interface. Comments added\n\
             # here are replaced the next time a tag is saved.\n\
             #\n\
             # A name ending in ':' colours a whole family, so \"tlp:\" would\n\
             # cover every tlp: tag at once.\n\
             \n",
        );
        for (name, tag) in &self.tags {
            out.push_str(&format!("[tags.\"{name}\"]\n"));
            out.push_str(&format!("colour = \"{}\"\n", tag.colour));
            if !tag.description.is_empty() {
                // Escaped because a description is free text and may contain
                // either character.
                let escaped = tag.description.replace('\\', "\\\\").replace('"', "\\\"");
                out.push_str(&format!("description = \"{escaped}\"\n"));
            }
            out.push('\n');
        }
        out
    }

    /// The colour for a tag: its own, else its family's, else `None`.
    ///
    /// The longest matching family wins, so `misp-event:` can differ from a
    /// broader `misp-` were one defined.
    pub fn colour_of(&self, tag: &str) -> Option<&str> {
        if let Some(known) = self.tags.get(tag) {
            return Some(&known.colour);
        }
        self.tags
            .iter()
            .filter(|(name, _)| name.ends_with(':') && tag.starts_with(name.as_str()))
            .max_by_key(|(name, _)| name.len())
            .map(|(_, tag)| tag.colour.as_str())
    }

    pub fn get(&self, name: &str) -> Option<&Tag> {
        self.tags.get(name)
    }

    pub fn entries(&self) -> impl Iterator<Item = (&String, &Tag)> {
        self.tags.iter()
    }

    /// How many tags are defined.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// Define or redefine one tag.
    pub fn set(&mut self, name: &str, colour: &str, description: &str) -> Result<(), String> {
        let name = name.trim();
        validate(name, colour)?;
        self.tags.insert(
            name.to_string(),
            Tag {
                colour: normalise_colour(colour),
                description: description.trim().to_string(),
            },
        );
        Ok(())
    }

    /// Forget a tag's presentation. Values keep the tag itself.
    pub fn remove(&mut self, name: &str) -> bool {
        self.tags.remove(name.trim()).is_some()
    }
}

/// Is this a usable tag name and colour?
fn validate(name: &str, colour: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("a tag needs a name".to_string());
    }
    if name.len() > MAX_NAME {
        return Err(format!("a tag name is at most {MAX_NAME} characters"));
    }
    // A comma separates tags on a value, so a tag containing one could never
    // be written to a value and read back as itself.
    if name.contains(',') {
        return Err("a tag cannot contain a comma, which is what separates tags".to_string());
    }
    if name.trim() != name {
        return Err("a tag cannot start or end with a space".to_string());
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("a tag cannot contain control characters".to_string());
    }
    validate_colour(colour)
}

fn validate_colour(colour: &str) -> Result<(), String> {
    let hex = colour.strip_prefix('#').ok_or("a colour starts with '#'")?;
    if hex.len() != 3 && hex.len() != 6 {
        return Err("a colour is #rgb or #rrggbb".to_string());
    }
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("a colour is hexadecimal".to_string());
    }
    Ok(())
}

fn normalise_colour(colour: &str) -> String {
    colour.trim().to_lowercase()
}

/// Split a value's tag field into its tags, dropping empties.
pub fn split(tags: &str) -> impl Iterator<Item = &str> {
    tags.split(',').map(str::trim).filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seeded_vocabulary_uses_misps_own_tlp_colours() {
        let vocabulary = Vocabulary::seeded();
        assert_eq!(vocabulary.colour_of("tlp:red"), Some("#FF2B2B"));
        assert_eq!(vocabulary.colour_of("tlp:green"), Some("#33FF00"));
    }

    /// A family colours every tag under it, which is the only way an open set
    /// of values can be coloured at all.
    #[test]
    fn a_family_colours_the_tags_under_it() {
        let vocabulary = Vocabulary::seeded();
        assert_eq!(
            vocabulary.colour_of("stix-type:ipv4-addr"),
            vocabulary.colour_of("stix-type:domain-name"),
            "two tags in one family should share its colour"
        );
        assert!(vocabulary.colour_of("stix-type:anything-at-all").is_some());
    }

    /// An exact entry beats the family it sits in, so one tag can be singled
    /// out without splitting the family.
    #[test]
    fn an_exact_tag_wins_over_its_family() {
        let mut vocabulary = Vocabulary::seeded();
        vocabulary.set("misp-type:", "#111111", "").unwrap();
        vocabulary.set("misp-type:md5", "#222222", "").unwrap();

        assert_eq!(vocabulary.colour_of("misp-type:md5"), Some("#222222"));
        assert_eq!(vocabulary.colour_of("misp-type:sha1"), Some("#111111"));
    }

    /// The longest family wins, so a narrower one can be carved out of a
    /// broader one.
    #[test]
    fn the_longest_family_wins() {
        let mut vocabulary = Vocabulary::default();
        vocabulary.set("a:", "#111111", "").unwrap();
        vocabulary.set("a:b:", "#222222", "").unwrap();

        assert_eq!(vocabulary.colour_of("a:b:c"), Some("#222222"));
        assert_eq!(vocabulary.colour_of("a:z"), Some("#111111"));
    }

    #[test]
    fn an_unknown_tag_has_no_colour_of_its_own() {
        assert_eq!(Vocabulary::seeded().colour_of("something-new"), None);
    }

    /// A tag with a comma could not be written to a value and read back as
    /// itself, so it is refused rather than silently split later.
    #[test]
    fn a_tag_cannot_contain_the_separator() {
        let mut vocabulary = Vocabulary::default();
        let refused = vocabulary.set("one,two", "#ffffff", "");
        assert!(refused.is_err(), "a comma in a tag must be refused");
        assert!(refused.unwrap_err().contains("comma"));
    }

    #[test]
    fn a_colour_must_be_hexadecimal() {
        let mut vocabulary = Vocabulary::default();
        assert!(vocabulary.set("t", "red", "").is_err());
        assert!(vocabulary.set("t", "#gggggg", "").is_err());
        assert!(vocabulary.set("t", "#12345", "").is_err());
        assert!(vocabulary.set("t", "#abc", "").is_ok());
        assert!(vocabulary.set("t", "#AABBCC", "").is_ok());
    }

    /// Written and read back unchanged, including a description with the
    /// characters that would break the file.
    #[test]
    fn a_vocabulary_survives_a_round_trip() {
        let mut vocabulary = Vocabulary::seeded();
        vocabulary
            .set("odd", "#abcdef", "a \"quoted\" back\\slash")
            .unwrap();

        let reloaded = Vocabulary::from_toml(&vocabulary.to_toml()).expect("valid TOML");
        assert_eq!(reloaded, vocabulary);
        assert_eq!(
            reloaded.get("odd").map(|t| t.description.as_str()),
            Some("a \"quoted\" back\\slash")
        );
    }

    /// A tag name containing a dot must not become a nested table, which is
    /// what an unquoted TOML key would do.
    #[test]
    fn a_dotted_tag_name_round_trips() {
        let mut vocabulary = Vocabulary::default();
        vocabulary.set("file.md5", "#123456", "").unwrap();

        let reloaded = Vocabulary::from_toml(&vocabulary.to_toml()).expect("valid TOML");
        assert!(
            reloaded.get("file.md5").is_some(),
            "{}",
            vocabulary.to_toml()
        );
    }

    /// A bad entry is dropped, and the good ones beside it still load. The
    /// file decides colours; refusing to start over one would be worse.
    #[test]
    fn a_malformed_entry_does_not_lose_the_rest() {
        let text = r##"
[tags."good"]
colour = "#ffffff"
[tags."bad"]
colour = "not a colour"
"##;
        let vocabulary = Vocabulary::from_toml(text).expect("the file itself parses");
        assert!(vocabulary.get("good").is_some());
        assert!(vocabulary.get("bad").is_none());
    }

    #[test]
    fn removing_a_tag_leaves_the_others() {
        let mut vocabulary = Vocabulary::seeded();
        let before = vocabulary.len();
        assert!(vocabulary.remove("tlp:red"));
        assert!(
            !vocabulary.remove("tlp:red"),
            "removing twice is not a change"
        );
        assert_eq!(vocabulary.len(), before - 1);
        assert!(vocabulary.get("tlp:green").is_some());
    }

    #[test]
    fn splitting_a_tag_field_drops_blanks_and_spaces() {
        let got: Vec<&str> = split(" a , ,b,, c ").collect();
        assert_eq!(got, vec!["a", "b", "c"]);
    }
}
