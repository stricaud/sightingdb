//! Turning a DNS query name into a (namespace, value) pair.
//!
//! A query looks like `<value labels>.<label>.<zone>`, where `<label>` selects
//! a configured namespace and decides how the value labels are read back.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};
use data_encoding::BASE32_NOPAD;

/// How the value labels of a query encode the stored value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Reversed octets, the DNSBL convention: `4.3.2.1` is `1.2.3.4`. IPv6 uses
    /// the reversed-nibble form that `ip6.arpa` uses.
    Ip,
    /// The labels are the value: `evil.com` is `"evil.com"`.
    Domain,
    /// base32 (RFC 4648, unpadded) of the value, for anything that will not
    /// survive being written as DNS labels.
    Base32,
}

impl Encoding {
    pub fn parse(raw: &str) -> Result<Encoding> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ip" => Ok(Encoding::Ip),
            "domain" => Ok(Encoding::Domain),
            "base32" => Ok(Encoding::Base32),
            other => bail!("unknown DNS encoding '{other}', expected ip, domain or base32"),
        }
    }
}

/// One namespace exposed over DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposed {
    /// The DNS label that selects this namespace.
    pub label: String,
    /// The database namespace it maps to.
    pub namespace: String,
    pub encoding: Encoding,
}

/// What a query resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup<'a> {
    pub exposed: &'a Exposed,
    pub value: String,
}

/// Split a query name into a namespace and a value.
///
/// `qlabels` and `zone` are both lowercased label lists without a root label.
/// Returns `None` when the name is outside the zone or names no configured
/// namespace — the caller turns that into NXDOMAIN or REFUSED.
pub fn resolve<'a>(
    qlabels: &[String],
    zone: &[String],
    exposed: &'a [Exposed],
) -> Option<Lookup<'a>> {
    // Must sit inside the zone, with room for a namespace label and at least
    // one value label beneath it.
    let rest = qlabels.strip_suffix(zone)?;
    let (label, value_labels) = rest.split_last()?;
    if value_labels.is_empty() {
        return None;
    }

    let exposed = exposed.iter().find(|e| e.label == *label)?;
    let value = decode(value_labels, exposed.encoding)?;

    Some(Lookup { exposed, value })
}

/// Read the value out of its labels. `None` for anything malformed, which is
/// simply a name that does not exist.
pub fn decode(labels: &[String], encoding: Encoding) -> Option<String> {
    match encoding {
        Encoding::Ip => decode_ip(labels),
        Encoding::Domain => Some(labels.join(".")),
        Encoding::Base32 => decode_base32(labels),
    }
}

fn decode_ip(labels: &[String]) -> Option<String> {
    match labels.len() {
        4 => {
            let mut octets = [0u8; 4];
            // Reversed, so the last label is the first octet.
            for (slot, label) in octets.iter_mut().zip(labels.iter().rev()) {
                *slot = parse_canonical_u8(label)?;
            }
            Some(Ipv4Addr::from(octets).to_string())
        }
        32 => {
            let mut nibbles = [0u8; 32];
            for (slot, label) in nibbles.iter_mut().zip(labels.iter().rev()) {
                let bytes = label.as_bytes();
                if bytes.len() != 1 {
                    return None;
                }
                *slot = (bytes[0] as char).to_digit(16)? as u8;
            }
            let mut octets = [0u8; 16];
            for (i, octet) in octets.iter_mut().enumerate() {
                *octet = (nibbles[i * 2] << 4) | nibbles[i * 2 + 1];
            }
            // Canonical compressed form, which is what a caller should have
            // stored via the HTTP API.
            Some(Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}

/// Reject non-canonical octets such as `01`, so that one address cannot be
/// spelled several ways.
fn parse_canonical_u8(label: &str) -> Option<u8> {
    if label.is_empty() || (label.len() > 1 && label.starts_with('0')) {
        return None;
    }
    label.parse().ok()
}

fn decode_base32(labels: &[String]) -> Option<String> {
    // DNS is case-insensitive and we lowercase on the way in, but the RFC 4648
    // alphabet is uppercase.
    let joined = labels.concat().to_ascii_uppercase();
    let bytes = BASE32_NOPAD.decode(joined.as_bytes()).ok()?;
    String::from_utf8(bytes).ok()
}

/// Encode a value the way a client would have to, used by the tests and by the
/// documentation examples.
#[cfg(test)]
pub fn encode_base32(value: &str) -> String {
    BASE32_NOPAD.encode(value.as_bytes()).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(name: &str) -> Vec<String> {
        name.split('.').map(str::to_string).collect()
    }

    fn exposed() -> Vec<Exposed> {
        vec![
            Exposed {
                label: "malware".into(),
                namespace: "malware/ips".into(),
                encoding: Encoding::Ip,
            },
            Exposed {
                label: "domains".into(),
                namespace: "malware/domains".into(),
                encoding: Encoding::Domain,
            },
            Exposed {
                label: "hashes".into(),
                namespace: "malware/hashes".into(),
                encoding: Encoding::Base32,
            },
        ]
    }

    // -- encodings ---------------------------------------------------------

    #[test]
    fn reversed_octets_are_an_ipv4_address() {
        assert_eq!(decode(&labels("4.3.2.1"), Encoding::Ip).unwrap(), "1.2.3.4");
        assert_eq!(
            decode(&labels("1.0.0.127"), Encoding::Ip).unwrap(),
            "127.0.0.1"
        );
        assert_eq!(
            decode(&labels("255.255.255.255"), Encoding::Ip).unwrap(),
            "255.255.255.255"
        );
    }

    /// One address must have exactly one spelling, or the same sighting could
    /// be looked up under names that disagree.
    #[test]
    fn non_canonical_octets_are_rejected() {
        assert_eq!(decode(&labels("01.2.3.4"), Encoding::Ip), None);
        assert_eq!(decode(&labels("4.3.2.256"), Encoding::Ip), None);
        assert_eq!(decode(&labels("4.3.2.-1"), Encoding::Ip), None);
        assert_eq!(decode(&labels("4.3.2.x"), Encoding::Ip), None);
        assert_eq!(decode(&labels("4.3.2."), Encoding::Ip), None);
    }

    #[test]
    fn the_wrong_number_of_octets_is_not_an_address() {
        assert_eq!(decode(&labels("3.2.1"), Encoding::Ip), None);
        assert_eq!(decode(&labels("5.4.3.2.1"), Encoding::Ip), None);
    }

    #[test]
    fn reversed_nibbles_are_an_ipv6_address() {
        // 2001:db8::1 in the ip6.arpa nibble form.
        let mut nibbles: Vec<String> = Vec::new();
        for ch in "20010db8000000000000000000000001".chars() {
            nibbles.push(ch.to_string());
        }
        nibbles.reverse();

        assert_eq!(decode(&nibbles, Encoding::Ip).unwrap(), "2001:db8::1");
    }

    #[test]
    fn malformed_nibbles_are_rejected() {
        let mut nibbles: Vec<String> = std::iter::repeat_n("0".to_string(), 32).collect();
        nibbles[5] = "zz".to_string();
        assert_eq!(decode(&nibbles, Encoding::Ip), None);

        nibbles[5] = "g".to_string();
        assert_eq!(decode(&nibbles, Encoding::Ip), None);
    }

    #[test]
    fn domain_labels_are_the_value() {
        assert_eq!(
            decode(&labels("evil.com"), Encoding::Domain).unwrap(),
            "evil.com"
        );
        assert_eq!(
            decode(&labels("a.b.evil.com"), Encoding::Domain).unwrap(),
            "a.b.evil.com"
        );
    }

    #[test]
    fn base32_round_trips() {
        for value in [
            "1.2.3.4",
            "evil.com",
            "d41d8cd98f00b204e9800998ecf8427e",
            "https://example.com/a?b=c",
        ] {
            let encoded = encode_base32(value);
            assert_eq!(
                decode(std::slice::from_ref(&encoded), Encoding::Base32).as_deref(),
                Some(value),
                "round trip failed for {value} via {encoded}"
            );
        }
    }

    /// A long value has to be split across labels, since one label caps at 63
    /// bytes. The chunks are read left to right.
    #[test]
    fn base32_spans_several_labels() {
        let value = "a".repeat(100);
        let encoded = encode_base32(&value);
        assert!(encoded.len() > 63);

        let chunks: Vec<String> = encoded
            .as_bytes()
            .chunks(63)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect();
        assert!(chunks.len() > 1);

        assert_eq!(
            decode(&chunks, Encoding::Base32).as_deref(),
            Some(&value[..])
        );
    }

    #[test]
    fn invalid_base32_is_not_a_value() {
        assert_eq!(decode(&labels("not!base32"), Encoding::Base32), None);
        assert_eq!(decode(&labels("1"), Encoding::Base32), None);
    }

    // -- resolution --------------------------------------------------------

    #[test]
    fn a_query_resolves_to_its_namespace_and_value() {
        let zone = labels("sdb.example.com");
        let exposed = exposed();

        let found = resolve(&labels("4.3.2.1.malware.sdb.example.com"), &zone, &exposed).unwrap();
        assert_eq!(found.exposed.namespace, "malware/ips");
        assert_eq!(found.value, "1.2.3.4");

        let found = resolve(&labels("evil.com.domains.sdb.example.com"), &zone, &exposed).unwrap();
        assert_eq!(found.exposed.namespace, "malware/domains");
        assert_eq!(found.value, "evil.com");
    }

    #[test]
    fn names_outside_the_zone_do_not_resolve() {
        let zone = labels("sdb.example.com");
        assert_eq!(
            resolve(&labels("4.3.2.1.malware.elsewhere.com"), &zone, &exposed()),
            None
        );
    }

    /// Only namespaces named in the configuration answer, so nothing else in
    /// the database is reachable without authentication.
    #[test]
    fn unexposed_namespaces_do_not_resolve() {
        let zone = labels("sdb.example.com");
        assert_eq!(
            resolve(
                &labels("4.3.2.1.secrets.sdb.example.com"),
                &zone,
                &exposed()
            ),
            None
        );
        assert_eq!(
            resolve(
                &labels("4.3.2.1._config.sdb.example.com"),
                &zone,
                &exposed()
            ),
            None
        );
    }

    #[test]
    fn the_zone_apex_and_a_bare_namespace_are_not_lookups() {
        let zone = labels("sdb.example.com");
        assert_eq!(resolve(&labels("sdb.example.com"), &zone, &exposed()), None);
        assert_eq!(
            resolve(&labels("malware.sdb.example.com"), &zone, &exposed()),
            None
        );
    }

    #[test]
    fn encodings_parse_from_configuration() {
        assert_eq!(Encoding::parse("ip").unwrap(), Encoding::Ip);
        assert_eq!(Encoding::parse(" Domain ").unwrap(), Encoding::Domain);
        assert_eq!(Encoding::parse("BASE32").unwrap(), Encoding::Base32);
        assert!(Encoding::parse("rot13").is_err());
    }
}
