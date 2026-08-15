//! UDP and TCP listeners.
//!
//! A UDP responder open to the internet is a reflection amplifier, so this
//! keeps responses small, rate limits per source address, and *drops* rather
//! than refuses once a source is over its budget — an error reply is still an
//! amplified packet.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::serialize::binary::BinDecodable;

use crate::dns::answer::Responder;
use crate::maintenance::Shutdown;

/// Largest response we will put in a UDP packet without EDNS. RFC 1035.
const DEFAULT_UDP_LIMIT: usize = 512;
/// Ceiling on what we will send even if a client advertises more, to keep the
/// amplification factor low.
const MAX_UDP_LIMIT: usize = 1232;
/// How often a blocked listener wakes to notice shutdown.
const POLL: Duration = Duration::from_millis(500);

pub fn spawn(
    responder: Arc<Responder>,
    listen: &str,
    threads: usize,
    rate_limit: u32,
    shutdown: Arc<Shutdown>,
) -> Result<Vec<JoinHandle<()>>> {
    let limiter = Arc::new(RateLimiter::new(rate_limit));
    let mut handles = Vec::new();

    let udp = UdpSocket::bind(listen).with_context(|| format!("binding UDP {listen}"))?;
    udp.set_read_timeout(Some(POLL))
        .context("setting the UDP read timeout")?;

    for n in 0..threads.max(1) {
        let socket = udp.try_clone().context("cloning the UDP socket")?;
        let responder = Arc::clone(&responder);
        let limiter = Arc::clone(&limiter);
        let shutdown = Arc::clone(&shutdown);
        handles.push(
            std::thread::Builder::new()
                .name(format!("sightingdb-dns-udp-{n}"))
                .spawn(move || udp_loop(&socket, &responder, &limiter, &shutdown))
                .context("starting a DNS UDP thread")?,
        );
    }

    // TCP is required for anything that will not fit in a datagram, and for
    // clients that simply prefer it.
    let tcp = TcpListener::bind(listen).with_context(|| format!("binding TCP {listen}"))?;
    tcp.set_nonblocking(true)
        .context("setting the TCP listener non-blocking")?;
    {
        let responder = Arc::clone(&responder);
        let limiter = Arc::clone(&limiter);
        let shutdown = Arc::clone(&shutdown);
        handles.push(
            std::thread::Builder::new()
                .name("sightingdb-dns-tcp".into())
                .spawn(move || tcp_loop(&tcp, &responder, &limiter, &shutdown))
                .context("starting the DNS TCP thread")?,
        );
    }

    Ok(handles)
}

fn udp_loop(socket: &UdpSocket, responder: &Responder, limiter: &RateLimiter, shutdown: &Shutdown) {
    let mut buf = [0u8; 4096];
    while !shutdown.is_stopped() {
        let (len, from) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            // The read timeout is how we notice shutdown.
            Err(_) => continue,
        };

        if !limiter.allow(from.ip()) {
            continue;
        }

        let Some(response) = handle(&buf[..len], responder) else {
            continue;
        };

        let limit = udp_limit(&response.request_edns_payload);
        let bytes = match encode(&response.message, limit) {
            Some(bytes) => bytes,
            None => continue,
        };

        let _ = socket.send_to(&bytes, from);
    }
}

fn tcp_loop(
    listener: &TcpListener,
    responder: &Responder,
    limiter: &RateLimiter,
    shutdown: &Shutdown,
) {
    while !shutdown.is_stopped() {
        match listener.accept() {
            Ok((stream, from)) => {
                if !limiter.allow(from.ip()) {
                    continue;
                }
                // Handled inline: a DNS/TCP exchange is one short request and
                // reply, and the timeouts below bound how long it can take.
                let _ = serve_tcp(stream, responder);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => std::thread::sleep(POLL),
        }
    }
}

fn serve_tcp(mut stream: TcpStream, responder: &Responder) -> std::io::Result<()> {
    // Bound how long a slow or stalled peer can hold the thread.
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // DNS over TCP frames each message with a two byte length.
    let mut length = [0u8; 2];
    stream.read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 || length > 8192 {
        return Ok(());
    }

    let mut buf = vec![0u8; length];
    stream.read_exact(&mut buf)?;

    let Some(response) = handle(&buf, responder) else {
        return Ok(());
    };
    // TCP has no 512 byte problem, so nothing is truncated here.
    let Some(bytes) = encode(&response.message, usize::MAX) else {
        return Ok(());
    };

    stream.write_all(&(bytes.len() as u16).to_be_bytes())?;
    stream.write_all(&bytes)
}

struct Handled {
    message: Message,
    request_edns_payload: Option<u16>,
}

/// Parse a query and produce the reply, or `None` if the bytes were too
/// malformed to answer at all.
fn handle(bytes: &[u8], responder: &Responder) -> Option<Handled> {
    match Message::from_bytes(bytes) {
        Ok(request) => {
            // Never reply to a reply: that is how two servers are made to
            // shout at each other forever.
            if request.metadata.message_type == MessageType::Response {
                return None;
            }
            let request_edns_payload = request.edns.as_ref().map(|e| e.max_payload());
            Some(Handled {
                message: responder.respond(&request),
                request_edns_payload,
            })
        }
        // Unparseable, but if the first two bytes look like an id we can still
        // be polite about it.
        Err(_) if bytes.len() >= 2 => {
            let id = u16::from_be_bytes([bytes[0], bytes[1]]);
            Some(Handled {
                message: Message::error_msg(id, OpCode::Query, ResponseCode::FormErr),
                request_edns_payload: None,
            })
        }
        Err(_) => None,
    }
}

fn udp_limit(advertised: &Option<u16>) -> usize {
    match advertised {
        Some(payload) => (*payload as usize).clamp(DEFAULT_UDP_LIMIT, MAX_UDP_LIMIT),
        None => DEFAULT_UDP_LIMIT,
    }
}

/// Serialize, falling back to a truncated reply that tells the client to come
/// back over TCP.
fn encode(message: &Message, limit: usize) -> Option<Vec<u8>> {
    let bytes = message.to_vec().ok()?;
    if bytes.len() <= limit {
        return Some(bytes);
    }
    message.truncate().to_vec().ok()
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

const SHARDS: usize = 16;

/// A fixed one-second window per source address.
///
/// Sharded so that a busy server does not serialize every query behind one
/// lock, and self-clearing so that a flood of spoofed sources cannot grow the
/// table beyond a second's worth of addresses.
struct RateLimiter {
    limit: u32,
    started: Instant,
    shards: Vec<Mutex<Shard>>,
    hasher: std::collections::hash_map::RandomState,
    /// Dropped queries, for the log.
    dropped: AtomicU64,
}

#[derive(Default)]
struct Shard {
    window: u64,
    counts: HashMap<IpAddr, u32>,
}

impl RateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            started: Instant::now(),
            shards: (0..SHARDS).map(|_| Mutex::new(Shard::default())).collect(),
            hasher: std::collections::hash_map::RandomState::new(),
            dropped: AtomicU64::new(0),
        }
    }

    fn allow(&self, source: IpAddr) -> bool {
        if self.limit == 0 {
            return true;
        }

        let window = self.started.elapsed().as_secs();
        let shard = &self.shards[(self.hasher.hash_one(source) as usize) % SHARDS];

        let mut shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
        if shard.window != window {
            shard.window = window;
            shard.counts.clear();
        }

        let count = shard.counts.entry(source).or_insert(0);
        *count += 1;

        if *count > self.limit {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            false
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn a_zero_limit_means_unlimited() {
        let limiter = RateLimiter::new(0);
        for _ in 0..10_000 {
            assert!(limiter.allow(ip(1)));
        }
    }

    #[test]
    fn a_source_is_cut_off_at_its_limit() {
        let limiter = RateLimiter::new(5);

        for i in 0..5 {
            assert!(limiter.allow(ip(1)), "query {i} should have been allowed");
        }
        assert!(!limiter.allow(ip(1)));
        assert!(!limiter.allow(ip(1)));
        assert_eq!(limiter.dropped.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn sources_are_budgeted_independently() {
        let limiter = RateLimiter::new(2);

        assert!(limiter.allow(ip(1)));
        assert!(limiter.allow(ip(1)));
        assert!(!limiter.allow(ip(1)));

        // A different address is unaffected by the first one's flood.
        assert!(limiter.allow(ip(2)));
        assert!(limiter.allow(ip(2)));
    }

    #[test]
    fn the_table_does_not_grow_without_bound() {
        let limiter = RateLimiter::new(1);
        for i in 0..=255 {
            limiter.allow(ip(i));
        }

        let total: usize = limiter
            .shards
            .iter()
            .map(|s| s.lock().unwrap().counts.len())
            .sum();
        // One window's worth of sources, no more.
        assert!(total <= 256, "table held {total} entries");
    }

    // -- response sizing ---------------------------------------------------

    #[test]
    fn without_edns_a_response_is_capped_at_512() {
        assert_eq!(udp_limit(&None), DEFAULT_UDP_LIMIT);
    }

    #[test]
    fn edns_raises_the_cap_but_only_so_far() {
        assert_eq!(udp_limit(&Some(4096)), MAX_UDP_LIMIT);
        assert_eq!(udp_limit(&Some(1232)), 1232);
        // A client asking for less than the floor still gets the floor.
        assert_eq!(udp_limit(&Some(200)), DEFAULT_UDP_LIMIT);
    }

    #[test]
    fn an_oversized_response_comes_back_truncated() {
        use hickory_proto::op::Query;
        use hickory_proto::rr::rdata::TXT;
        use hickory_proto::rr::{Name, RData, Record, RecordType};

        let mut message = Message::response(1, OpCode::Query);
        let name = Name::parse("a.b.example.com.", None).unwrap();
        message.add_query(Query::query(name.clone(), RecordType::TXT));
        for _ in 0..40 {
            message.answers.push(Record::from_rdata(
                name.clone(),
                60,
                RData::TXT(TXT::new(vec!["x".repeat(200)])),
            ));
        }

        let full = message.to_vec().unwrap();
        assert!(full.len() > DEFAULT_UDP_LIMIT);

        let encoded = encode(&message, DEFAULT_UDP_LIMIT).unwrap();
        let decoded = Message::from_bytes(&encoded).unwrap();
        assert!(decoded.metadata.truncation, "TC should be set");
        assert!(encoded.len() <= DEFAULT_UDP_LIMIT);
    }

    #[test]
    fn a_small_response_is_sent_whole() {
        let message = Message::response(1, OpCode::Query);
        let encoded = encode(&message, DEFAULT_UDP_LIMIT).unwrap();
        assert!(!Message::from_bytes(&encoded).unwrap().metadata.truncation);
    }
}
