//! Ingesting sightings from a ZeroMQ publisher.
//!
//! This is a SUB socket that connects out to a publisher we were configured to
//! trust — MISP's, typically — and turns what it hears into sightings. The
//! implementation is the pure-Rust `zeromq` crate rather than bindings to
//! libzmq, so release binaries stay self-contained; it speaks ZMTP to real
//! libzmq publishers, which is what MISP uses.

pub mod misp;
pub mod stix;

use std::sync::Arc;
use std::time::{Duration, Instant};

use zeromq::{Socket, SocketRecv, SubSocket, ZmqMessage};

use crate::handlers::SharedState;
use crate::ingest::misp::{Mapping, Sighting};
use crate::maintenance::Shutdown;
use crate::sighting_writer;

/// How a publisher's messages are shaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// MISP's `<topic> <json>` publications.
    Misp,
    /// SightingDB's own batch format, `{"items": [{namespace, value, ...}]}`.
    Native,
}

impl Format {
    pub fn parse(raw: &str) -> anyhow::Result<Format> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "misp" => Ok(Format::Misp),
            "native" => Ok(Format::Native),
            other => anyhow::bail!("unknown zmq format '{other}', expected misp or native"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub endpoint: String,
    pub topics: Vec<String>,
    pub format: Format,
    pub mapping: Mapping,
    /// TTL applied to ingested sightings; 0 leaves them permanent.
    pub ttl: u64,
    /// Seconds to wait before reconnecting after the stream drops.
    pub reconnect: u64,
}

/// Subscribe and keep ingesting until shutdown.
///
/// A publisher going away is normal — MISP restarts — so a dropped connection
/// is logged and retried rather than treated as fatal.
pub async fn run(state: Arc<SharedState>, settings: Settings, shutdown: Arc<Shutdown>) {
    let backoff = Duration::from_secs(settings.reconnect.max(1));

    while !shutdown.is_stopped() {
        match subscribe(&settings).await {
            Ok(socket) => {
                log::info!(
                    "ZMQ ingest connected to {} ({} topic(s))",
                    settings.endpoint,
                    settings.topics.len()
                );
                consume(socket, &state, &settings, &shutdown).await;
                if shutdown.is_stopped() {
                    return;
                }
                log::warn!(
                    "ZMQ ingest stream from {} ended, reconnecting in {}s",
                    settings.endpoint,
                    backoff.as_secs()
                );
            }
            Err(e) => log::warn!(
                "ZMQ ingest could not connect to {}: {e}. Retrying in {}s",
                settings.endpoint,
                backoff.as_secs()
            ),
        }

        actix_web::rt::time::sleep(backoff).await;
    }
}

async fn subscribe(settings: &Settings) -> anyhow::Result<SubSocket> {
    let mut socket = SubSocket::new();
    socket.connect(&settings.endpoint).await?;

    if settings.topics.is_empty() {
        // An empty subscription matches everything, which is ZeroMQ's own rule.
        socket.subscribe("").await?;
    } else {
        for topic in &settings.topics {
            socket.subscribe(topic).await?;
        }
    }

    Ok(socket)
}

async fn consume(
    mut socket: SubSocket,
    state: &SharedState,
    settings: &Settings,
    shutdown: &Shutdown,
) {
    let mut stats = Stats::new();

    // No timeout on `recv`: cancelling it every tick risks dropping a message
    // mid-stream. Shutdown drops this whole task when the runtime stops, and
    // the check below gets us out promptly once traffic is flowing.
    while let Ok(message) = socket.recv().await {
        let Some(body) = body_of(&message) else {
            stats.malformed += 1;
            continue;
        };

        let parsed = match settings.format {
            Format::Misp => misp::parse(misp::strip_topic(&body), &settings.mapping),
            Format::Native => misp::parse_native(misp::strip_topic(&body)),
        };

        match parsed {
            Ok(sightings) => {
                if sightings.is_empty() {
                    stats.ignored += 1;
                }
                for sighting in sightings {
                    match record(&state.db, settings.ttl, &sighting) {
                        Ok(()) => stats.written += 1,
                        Err(e) => {
                            stats.rejected += 1;
                            log::debug!(
                                "ZMQ ingest rejected {}/{}: {e}",
                                sighting.namespace,
                                sighting.value
                            );
                        }
                    }
                }
            }
            Err(e) => {
                stats.malformed += 1;
                log::debug!("ZMQ ingest could not parse a message: {e}");
            }
        }

        stats.maybe_report();

        if shutdown.is_stopped() {
            break;
        }
    }

    stats.report();
}

/// Write one parsed sighting, honouring its count and observation window.
///
/// A source that reports "seen 5 times between A and B" becomes one write at A
/// and the rest at B, so the stored `first_seen`/`last_seen` bracket the real
/// window rather than collapsing to a single instant.
pub fn record(
    db: &crate::db::Database,
    ttl: u64,
    sighting: &Sighting,
) -> Result<(), crate::error::ApiError> {
    let ttl = (ttl > 0).then_some(ttl);
    let first = match sighting.timestamp {
        Some(seconds) => Some(sighting_writer::timestamp_to_instant(seconds)?),
        None => None,
    };
    let last = match sighting.last_timestamp {
        Some(seconds) => Some(sighting_writer::timestamp_to_instant(seconds)?),
        None => first,
    };

    for n in 0..sighting.count.max(1) {
        let when = if n == 0 { first } else { last };
        sighting_writer::write(db, &sighting.namespace, &sighting.value, when, ttl)?;
    }
    Ok(())
}

/// The message body, whether the publisher used one frame with the topic
/// inline or put the topic in a frame of its own.
fn body_of(message: &ZmqMessage) -> Option<String> {
    let frame = match message.len() {
        0 => return None,
        1 => message.get(0)?,
        // Multi-frame: the topic is frame 0 and the payload is the last frame.
        n => message.get(n - 1)?,
    };
    String::from_utf8(frame.to_vec()).ok()
}

/// Counters, reported occasionally so a busy feed does not flood the log.
struct Stats {
    written: u64,
    rejected: u64,
    ignored: u64,
    malformed: u64,
    since: Instant,
}

impl Stats {
    const REPORT_EVERY: Duration = Duration::from_secs(60);

    fn new() -> Self {
        Self {
            written: 0,
            rejected: 0,
            ignored: 0,
            malformed: 0,
            since: Instant::now(),
        }
    }

    fn maybe_report(&mut self) {
        if self.since.elapsed() >= Self::REPORT_EVERY {
            self.report();
            *self = Self::new();
        }
    }

    fn report(&self) {
        if self.written == 0 && self.malformed == 0 && self.rejected == 0 {
            return;
        }
        log::info!(
            "ZMQ ingest: {} sighting(s) written, {} rejected, {} message(s) with nothing to \
             ingest, {} malformed",
            self.written,
            self.rejected,
            self.ignored,
            self.malformed
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn settings(format: Format) -> Settings {
        Settings {
            endpoint: "tcp://127.0.0.1:1".into(),
            topics: vec!["misp_json_attribute".into()],
            format,
            mapping: Mapping {
                types: HashMap::from([("ip-src".to_string(), "misp/ips".to_string())]),
                default_namespace: None,
                require_to_ids: false,
            },
            ttl: 0,
            reconnect: 5,
        }
    }

    #[test]
    fn formats_parse_from_configuration() {
        assert_eq!(Format::parse("misp").unwrap(), Format::Misp);
        assert_eq!(Format::parse(" Native ").unwrap(), Format::Native);
        assert!(Format::parse("avro").is_err());
    }

    #[test]
    fn a_sighting_is_written_with_its_timestamp() {
        let state = SharedState::new(false);
        let settings = settings(Format::Misp);

        record(
            &state.db,
            settings.ttl,
            &Sighting::once("misp/ips", "1.2.3.4", Some(1_600_000_000)),
        )
        .unwrap();

        let view = state.db.view("misp/ips", "1.2.3.4", 0, false).unwrap();
        assert_eq!(view.first_seen, 1_600_000_000);
        assert_eq!(view.ttl, 0);
    }

    #[test]
    fn a_configured_ttl_is_applied_to_ingested_sightings() {
        let state = SharedState::new(false);
        let mut settings = settings(Format::Misp);
        settings.ttl = 3600;

        record(
            &state.db,
            settings.ttl,
            &Sighting::once("misp/ips", "1.2.3.4", None),
        )
        .unwrap();

        assert_eq!(
            state.db.view("misp/ips", "1.2.3.4", 0, false).unwrap().ttl,
            3600
        );
    }

    /// A publisher must not be able to reach the tree holding API keys, even
    /// though it can otherwise choose its own namespace in the native format.
    #[test]
    fn a_publisher_cannot_write_to_the_config_tree() {
        let state = SharedState::new(false);

        let refused = record(
            &state.db,
            settings(Format::Native).ttl,
            &Sighting::once("_config/acl/apikeys/mine", "x", None),
        );

        assert!(refused.is_err());
        assert!(!state.db.namespace_exists("_config/acl/apikeys/mine"));
    }

    #[test]
    fn the_body_is_found_in_single_and_multi_frame_messages() {
        let single = ZmqMessage::from("misp_json_attribute {}");
        assert_eq!(body_of(&single).unwrap(), "misp_json_attribute {}");

        let mut multi = ZmqMessage::from("misp_json_attribute");
        multi.push_back("{\"Attribute\": {}}".into());
        assert_eq!(body_of(&multi).unwrap(), "{\"Attribute\": {}}");
    }

    #[test]
    fn an_end_to_end_misp_frame_lands_in_the_database() {
        let state = SharedState::new(false);
        let settings = settings(Format::Misp);

        let frame = r#"misp_json_attribute {"Attribute": {"type": "ip-src",
                       "value": "1.2.3.4", "timestamp": "1600000000"}}"#;
        let sightings = misp::parse(misp::strip_topic(frame), &settings.mapping).unwrap();
        for sighting in &sightings {
            record(&state.db, settings.ttl, sighting).unwrap();
        }

        assert_eq!(state.db.count("misp/ips", "1.2.3.4"), 1);
        // Ingest counts towards consensus like any other write.
        assert_eq!(state.db.count(crate::db::ALL_NAMESPACE, "1.2.3.4"), 1);
    }
}
