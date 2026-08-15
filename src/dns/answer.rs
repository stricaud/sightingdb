//! Turning a parsed DNS query into an answer.
//!
//! The conventions are the ones DNSBL clients already expect: a name that was
//! never seen is NXDOMAIN, and a name that was seen answers with a `127.0.0.x`
//! address whose last octet says roughly how often. That makes SightingDB
//! usable from anything that can already consult a blocklist, with the TXT
//! record carrying the detail for clients that want it.

use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, NS, SOA, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use crate::attribute::AttributeView;
use crate::dns::name::{Exposed, resolve};
use crate::error::ApiError;
use crate::handlers::SharedState;
use crate::sighting_reader;

/// Everything the responder needs, built once at startup.
pub struct Responder {
    state: Arc<SharedState>,
    zone: Name,
    zone_labels: Vec<String>,
    exposed: Vec<Exposed>,
    ttl: u32,
    /// Whether a DNS lookup counts as a search. Off by default: it is an
    /// unauthenticated write path.
    shadow: bool,
}

impl Responder {
    pub fn new(
        state: Arc<SharedState>,
        zone: Name,
        exposed: Vec<Exposed>,
        ttl: u32,
        shadow: bool,
    ) -> Self {
        let zone_labels = labels_of(&zone);
        Self {
            state,
            zone,
            zone_labels,
            exposed,
            ttl,
            shadow,
        }
    }

    /// Answer one query. Always returns a message; the caller decides how to
    /// put it on the wire.
    pub fn respond(&self, request: &Message) -> Message {
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.authoritative = true;

        let mut response = Message::new(metadata.id, MessageType::Response, metadata.op_code);
        response.metadata = metadata;

        // We serve one zone authoritatively and do nothing else.
        if request.metadata.op_code != OpCode::Query {
            response.metadata.response_code = ResponseCode::NotImp;
            return response;
        }

        let Some(query) = request.queries.first() else {
            response.metadata.response_code = ResponseCode::FormErr;
            return response;
        };
        response.add_query(query.clone());

        if query.query_class() != DNSClass::IN {
            response.metadata.response_code = ResponseCode::NotImp;
            return response;
        }

        match self.answer(query) {
            Outcome::Answers(records) => {
                response.metadata.response_code = ResponseCode::NoError;
                response.answers = records;
            }
            // A name that exists but has no data of this type still needs the
            // SOA, so resolvers cache the negative for the right length.
            Outcome::NoData => {
                response.metadata.response_code = ResponseCode::NoError;
                response.authorities = vec![self.soa_record()];
            }
            Outcome::NxDomain => {
                response.metadata.response_code = ResponseCode::NXDomain;
                response.authorities = vec![self.soa_record()];
            }
            Outcome::Refused => {
                response.metadata.response_code = ResponseCode::Refused;
            }
        }

        response
    }

    fn answer(&self, query: &Query) -> Outcome {
        let qname = query.name();
        let qlabels = labels_of(qname);

        // Outside our zone entirely: say so rather than pretending the name
        // does not exist, and never act as an open resolver.
        if !qlabels.ends_with(&self.zone_labels) {
            return Outcome::Refused;
        }

        if qlabels.len() == self.zone_labels.len() {
            return self.answer_apex(query.query_type());
        }

        let Some(lookup) = resolve(&qlabels, &self.zone_labels, &self.exposed) else {
            return Outcome::NxDomain;
        };

        let view = match sighting_reader::read(
            &self.state.db,
            &lookup.exposed.namespace,
            &lookup.value,
            false,
            self.shadow,
        ) {
            Ok(view) => view,
            // Never seen, or the namespace is gone: both are "no such name" as
            // far as a DNS client is concerned.
            Err(ApiError::NotFound(_)) => return Outcome::NxDomain,
            Err(_) => return Outcome::Refused,
        };

        match query.query_type() {
            RecordType::A => Outcome::Answers(vec![self.a_record(query.name(), &view)]),
            RecordType::TXT => Outcome::Answers(vec![self.txt_record(query.name(), &view)]),
            RecordType::ANY => Outcome::Answers(vec![
                self.a_record(query.name(), &view),
                self.txt_record(query.name(), &view),
            ]),
            _ => Outcome::NoData,
        }
    }

    fn answer_apex(&self, query_type: RecordType) -> Outcome {
        match query_type {
            RecordType::SOA => Outcome::Answers(vec![self.soa_record()]),
            RecordType::NS => Outcome::Answers(vec![Record::from_rdata(
                self.zone.clone(),
                self.ttl,
                RData::NS(NS(self.zone.clone())),
            )]),
            _ => Outcome::NoData,
        }
    }

    fn a_record(&self, name: &Name, view: &AttributeView) -> Record {
        let address = std::net::Ipv4Addr::new(127, 0, 0, magnitude(view.count));
        Record::from_rdata(name.clone(), self.ttl, RData::A(A(address)))
    }

    fn txt_record(&self, name: &Name, view: &AttributeView) -> Record {
        let text = format!(
            "count={} first_seen={} last_seen={} consensus={}",
            view.count, view.first_seen, view.last_seen, view.consensus
        );
        Record::from_rdata(name.clone(), self.ttl, RData::TXT(TXT::new(vec![text])))
    }

    fn soa_record(&self) -> Record {
        let soa = SOA::new(
            self.zone.clone(),
            // No mailbox to give, so the conventional placeholder.
            Name::from_labels(vec![b"hostmaster".to_vec()])
                .unwrap_or_else(|_| Name::root())
                .append_domain(&self.zone)
                .unwrap_or_else(|_| self.zone.clone()),
            1,
            // Nothing ever transfers this zone, so the slave timers are
            // nominal; `minimum` is the one that matters, since it caps how
            // long a resolver caches an NXDOMAIN.
            3600,
            600,
            86_400,
            self.ttl,
        );
        Record::from_rdata(self.zone.clone(), self.ttl, RData::SOA(soa))
    }
}

enum Outcome {
    Answers(Vec<Record>),
    NoData,
    NxDomain,
    Refused,
}

/// The last octet of the `127.0.0.x` answer: how many times the value was seen,
/// by order of magnitude. 1 is once, 2 is single digits, 3 is tens, and so on.
/// A DNSBL client that only checks "did I get an address" still works.
fn magnitude(count: u64) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2..=9 => 2,
        10..=99 => 3,
        100..=999 => 4,
        1_000..=9_999 => 5,
        10_000..=99_999 => 6,
        100_000..=999_999 => 7,
        1_000_000..=9_999_999 => 8,
        _ => 9,
    }
}

/// A name as lowercase label strings, without the root label.
fn labels_of(name: &Name) -> Vec<String> {
    name.iter()
        .map(|label| String::from_utf8_lossy(label).to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::WriteOpts;
    use crate::dns::name::Encoding;
    use chrono::Utc;

    fn responder(shadow: bool) -> Responder {
        let state = Arc::new(SharedState::new(false));
        state.db.write(
            "malware/ips",
            "1.2.3.4",
            Utc::now(),
            WriteOpts {
                consensus: true,
                ttl: None,
            },
        );
        state.db.write(
            "malware/domains",
            "evil.com",
            Utc::now(),
            WriteOpts {
                consensus: true,
                ttl: None,
            },
        );
        state.db.write(
            "secrets",
            "hidden",
            Utc::now(),
            WriteOpts {
                consensus: true,
                ttl: None,
            },
        );

        Responder::new(
            state,
            Name::parse("sdb.example.com.", None).unwrap(),
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
            ],
            60,
            shadow,
        )
    }

    fn ask(responder: &Responder, name: &str, query_type: RecordType) -> Message {
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::parse(name, Some(&Name::root())).unwrap(),
            query_type,
        ));
        responder.respond(&request)
    }

    #[test]
    fn a_known_value_answers_with_a_loopback_address() {
        let r = responder(false);
        let response = ask(&r, "4.3.2.1.malware.sdb.example.com.", RecordType::A);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.metadata.authoritative);
        let RData::A(a) = &response.answers[0].data else {
            panic!("expected an A record, got {:?}", response.answers)
        };
        assert_eq!(a.0, std::net::Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn the_last_octet_grows_with_the_count() {
        assert_eq!(magnitude(1), 1);
        assert_eq!(magnitude(9), 2);
        assert_eq!(magnitude(10), 3);
        assert_eq!(magnitude(999), 4);
        assert_eq!(magnitude(u64::MAX), 9);
    }

    #[test]
    fn a_txt_query_carries_the_detail() {
        let r = responder(false);
        let response = ask(&r, "4.3.2.1.malware.sdb.example.com.", RecordType::TXT);

        let RData::TXT(txt) = &response.answers[0].data else {
            panic!("expected TXT")
        };
        let text = txt.to_string();
        assert!(text.contains("count=1"), "{text}");
        assert!(text.contains("consensus=1"), "{text}");
    }

    #[test]
    fn a_domain_namespace_uses_the_labels_directly() {
        let r = responder(false);
        let response = ask(&r, "evil.com.domains.sdb.example.com.", RecordType::A);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
    }

    #[test]
    fn an_unknown_value_is_nxdomain_with_an_soa() {
        let r = responder(false);
        let response = ask(&r, "9.9.9.9.malware.sdb.example.com.", RecordType::A);

        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        // The SOA is what lets resolvers cache the negative answer.
        assert_eq!(response.authorities.len(), 1);
    }

    /// The ACL does not apply to DNS, so only namespaces named in the
    /// configuration may be reachable — everything else must look absent.
    #[test]
    fn unexposed_namespaces_are_invisible() {
        let r = responder(false);

        for name in [
            "hidden.secrets.sdb.example.com.",
            "hidden._config.sdb.example.com.",
        ] {
            let response = ask(&r, name, RecordType::A);
            assert_eq!(
                response.metadata.response_code,
                ResponseCode::NXDomain,
                "{name}"
            );
            assert!(response.answers.is_empty(), "{name}");
        }
    }

    /// Answering for names we are not authoritative for would make this an
    /// open resolver.
    #[test]
    fn names_outside_the_zone_are_refused() {
        let r = responder(false);
        let response = ask(&r, "www.google.com.", RecordType::A);

        assert_eq!(response.metadata.response_code, ResponseCode::Refused);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn the_apex_serves_soa_and_ns() {
        let r = responder(false);

        let soa = ask(&r, "sdb.example.com.", RecordType::SOA);
        assert_eq!(soa.metadata.response_code, ResponseCode::NoError);
        assert!(matches!(&soa.answers[0].data, RData::SOA(_)));

        let ns = ask(&r, "sdb.example.com.", RecordType::NS);
        assert!(matches!(&ns.answers[0].data, RData::NS(_)));
    }

    #[test]
    fn an_unsupported_type_is_nodata_not_nxdomain() {
        let r = responder(false);
        let response = ask(&r, "4.3.2.1.malware.sdb.example.com.", RecordType::MX);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
        assert_eq!(response.authorities.len(), 1);
    }

    #[test]
    fn shadow_sightings_are_off_unless_asked_for() {
        let r = responder(false);
        ask(&r, "4.3.2.1.malware.sdb.example.com.", RecordType::A);
        assert_eq!(r.state.db.count("_shadow/malware/ips", "1.2.3.4"), 0);

        let r = responder(true);
        ask(&r, "4.3.2.1.malware.sdb.example.com.", RecordType::A);
        assert_eq!(r.state.db.count("_shadow/malware/ips", "1.2.3.4"), 1);
    }

    #[test]
    fn queries_are_echoed_and_the_id_preserved() {
        let r = responder(false);
        let mut request = Message::query();
        request.metadata.id = 0x1234;
        request.add_query(Query::query(
            Name::parse("4.3.2.1.malware.sdb.example.com.", None).unwrap(),
            RecordType::A,
        ));

        let response = r.respond(&request);

        assert_eq!(response.metadata.id, 0x1234);
        assert_eq!(response.metadata.message_type, MessageType::Response);
        assert_eq!(response.queries.len(), 1);
    }

    #[test]
    fn a_query_with_no_question_is_a_format_error() {
        let r = responder(false);
        let response = r.respond(&Message::query());

        assert_eq!(response.metadata.response_code, ResponseCode::FormErr);
    }
}
