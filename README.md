<p align="center"><img src="doc/sightingdb-logo3_128.png"/></p>

SightingDB is a database designed for Sightings, a technique to count items. This is helpful for Threat Intelligence as Sightings allow
to enrich indicators or attributes with Observations, rather than Reputation.

Simply speaking, by pushing data to SightingDB, you will get the first time it was observed, the last time, its count.

However, it will also provide the following features:
* Keep track of how many times something was searched
* Keep track of the hourly statistics per item
* Get the consensus for each item (how many namespaces contain the same value)
* Expire data with a per-value TTL
* Answer lookups over DNS, using the DNSBL conventions security tooling already speaks
* Ingest from a MISP ZeroMQ feed, and import STIX 2.1 bundles
* Browse namespaces and values in a browser, with a histogram of when each value was seen

SightingDB is designed to scale writing and reading. There is no global lock: namespaces are locked independently, and within a namespace each value has its own lock, so concurrent writes to different values never contend.

The database is held in memory and snapshotted to disk (see `dbdir` below). Set no `dbdir` to run purely in memory.

Getting started
===============

	$ cargo install sightingdb
	$ sightingdb --setup

`--setup` asks a few questions, prints exactly what it intends to do, and only
then does it: directories with sensible modes, a configuration, a self-signed
certificate, an admin API key, and a systemd unit or launchd job. Without root
it installs under `~/.sightingdb` for the current user; with `sudo` on Linux it
installs system-wide under `/etc` and `/var/lib` and creates a `sightingdb`
service account.

Nothing existing is replaced without being asked, file by file, and API keys
and certificates are never replaced at all — re-running setup on an installed
system keeps them. The admin key is shown once, when it is first created.

Building
========

1) Make sure you have Rust and Cargo installed. The toolchain is pinned in `rust-toolchain.toml`; rustup will fetch it automatically.
2) Run `make` (or `cargo build`).

You will need OpenSSL development headers to build (`libssl-dev` on Debian/Ubuntu, `openssl` from Homebrew on macOS).

Running
=======

To run from the source directory:

1. Generate a certificate: `./target/debug/sightingdb -c etc/sightingdb.toml --install-selfsigned-keys`
2. Start the daemon: `./target/debug/sightingdb -c etc/sightingdb.toml`

`--install-selfsigned-keys` writes a self-signed certificate and a `0600` key at
the configured `ssl_cert` and `ssl_key` paths and exits. It never overwrites an
existing file, so pointing those settings at a real certificate is safe. The
generated certificate names `localhost`, `127.0.0.1` and `::1`, lasts a year,
and is for getting started — clients have to skip verification (`curl -k`).

Set `ssl = false` in `[daemon]` to serve plain HTTP instead.

Without `-c`, the configuration is looked up in `/etc/sightingdb/sightingdb.toml` and then `~/.sightingdb/sightingdb.toml`.


Running as a service
--------------------

The recommended way to run SightingDB in the background is under a service
manager, which handles restarts, log capture and startup ordering for you. A
hardened systemd unit is provided:

	sudo install -m 0644 etc/sightingdb.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable --now sightingdb

Keep `daemonize = false` for that, and point log4rs at a console appender so the
logs land in the journal (`journalctl -u sightingdb`).

Setting `daemonize = true` instead makes SightingDB detach on its own: it
re-executes itself with `stdin` on `/dev/null`, `stdout` and `stderr` on the
`log_out` and `log_err` files, and its own process group, then the launcher
exits. A pid file is written to the first writable location out of
`/var/run/sightingdb.pid`, `~/.sightingdb/sightingdb.pid` or `./sightingdb.pid`,
and removed again on a clean shutdown.

Detaching by re-executing rather than by forking is deliberate. `fork` carries
over only the calling thread, so a forked daemon silently loses anything already
running in the background — including log4rs' own configuration reloader. The
child here starts from a clean `exec`, so `refresh_rate` keeps working. Nothing
changes directory either, so relative paths in the configuration keep resolving.

Send `SIGTERM` to stop: in-flight requests are drained, the database is written
out, and the pid file is removed.

Options
-------

	-c, --config <FILE>          Configuration file (default: see above)
	    --install-selfsigned-keys Write a self-signed cert and key, then exit
	    --import-stix <PATH>     Import STIX 2.1 bundles, then exit
	-l, --logging-config <FILE>  log4rs configuration file (default: etc/log4rs.yml)
	-k, --apikey <APIKEY>        Set the default API key, replacing the built-in 'changeme'
	-v, --verbose...             Increase verbosity

Client Demo
===========

Writing
-------
	$ curl -k https://localhost:9999/w/my/namespace/?val=127.0.0.1
	{"message":"ok","count":1}
	$ curl -k https://localhost:9999/w/another/namespace/?val=127.0.0.1
	{"message":"ok","count":1}
	$ curl -k https://localhost:9999/w/another/namespace/?val=127.0.0.1
	{"message":"ok","count":2}

Pass `timestamp=<unix seconds>` to record a sighting at a specific time; without it the sighting is recorded now.

Pass `ttl=<seconds>` to expire the value that long after it was last seen. Writing the value again pushes the deadline out; writing without `ttl=` leaves the existing one alone, and `ttl=0` clears it. Expired values read as `404` immediately and are reclaimed by the next sweep, which also gives back the consensus they were holding.

Reading
-------
	$ curl -k https://localhost:9999/r/my/namespace/?val=127.0.0.1
	{"value":"127.0.0.1","first_seen":1566624658,"last_seen":1566624658,"count":1,"tags":"","ttl":0,"consensus":2}

	$ curl -k https://localhost:9999/r/another/namespace/?val=127.0.0.1
	{"value":"127.0.0.1","first_seen":1566624686,"last_seen":1566624689,"count":2,"tags":"","ttl":0,"consensus":2}

	$ curl -k https://localhost:9999/rs/my/namespace/?val=127.0.0.1
	{"value":"127.0.0.1","first_seen":1593719022,"last_seen":1593721509,"count":10,"tags":"","ttl":0,"consensus":1,"stats":{"1593716400":2,"1593720000":8}}

Omit `val=` to list every value in a namespace:

	$ curl -k https://localhost:9999/r/my/namespace/
	{"attributes":[{"value":"127.0.0.1","first_seen":1566624658,"last_seen":1566624658,"count":1,"tags":"","ttl":0,"consensus":2}]}

Reading is recorded as a "shadow sighting" under `_shadow/<namespace>`, so you can see how often a value was searched for. Add `noshadow` to the query string to suppress that.

Bulk
----
	$ curl -k -X POST https://localhost:9999/wb -H 'Content-Type: application/json' \
	    -d '{"items":[{"namespace":"my/namespace","value":"127.0.0.1"}]}'
	{"message":"ok","written":1}

`timestamp`, `ttl` and `noshadow` are optional on each item.

Authentication
--------------
	$ curl -H 'Authorization: changeme' -k https://localhost:9999/w/my/namespace/?val=127.0.0.1
	{"message":"ok","count":1}

Authentication is on unless `authenticate=false` is set in the configuration. Keys and their permissions are declared in the `[acl]` section; see below.

REST Endpoints
==============
	/w: write (GET)
	/wb: write in bulk mode (POST)
	/r: read (GET)
	/rs: read with statistics (GET)
	/rb: read in bulk mode (POST)
	/rbs: read with statistics in bulk mode (POST)
	/d: delete (GET)
	/c: configure (GET, not implemented)
	/i: info (GET)

Status codes
------------

Every endpoint answers with JSON and a meaningful status code:

	200 OK         the request succeeded
	400 Bad Request malformed query string, JSON body, or a missing val=
	401 Unauthorized no Authorization header was sent
	403 Forbidden   unknown API key, or an attempt to reach the _config tree
	404 Not Found   no such namespace, or no such value inside it
	501 Not Implemented  /c

Configuration
=============

Either listener can be turned off, so one instance can serve HTTP, DNS, or
both. `enabled = false` under `[daemon]` runs DNS only; `enabled = false` under
`[dns]` (or simply omitting the section) runs HTTP only. Disabling both is a
startup error rather than a process that listens on nothing.

Beyond the listen address and TLS settings, `[daemon]` accepts:

	enabled           Serve the HTTP API (default true).

	dbdir             Directory for snapshots. Unset or blank runs in memory only.
	snapshot_interval Seconds between snapshots (default 300). 0 saves only on shutdown.
	sweep_interval    Seconds between eviction sweeps (default 60). 0 disables the sweeper.
	stats_retention   Hourly statistics buckets kept per value (default 0 = unlimited).
	shadow_ttl        Seconds a shadow sighting is kept (default 0 = forever).

The retention settings default to keeping everything, so upgrading an existing
install never starts discarding data on its own. The configuration shipped in
`etc/sightingdb.toml` sets 30-day windows for both, which is what bounds memory
growth — without them, statistics accumulate one bucket per hour per value and
`_shadow/*` grows for every distinct search, forever.

DNS lookups
===========

SightingDB can answer over DNS as well as HTTP, following the DNSBL/RBL
conventions, so anything that can already consult a blocklist — Postfix,
rspamd, Suricata, a shell script with `dig` — can query it unmodified.

	$ dig +short 4.3.2.1.malware.sdb.example.com
	127.0.0.1

	$ dig +short 9.9.9.9.malware.sdb.example.com
	127.0.0.3

	$ dig +short TXT 9.9.9.9.malware.sdb.example.com
	"count=15 first_seen=1786774648 last_seen=1786774648 consensus=1 ttl=86400 tags=\"\""

The TXT record carries every field the HTTP API reports. `tags` is quoted
because it is free-form, and a record too long for one DNS character-string is
split across several, which clients join back together.

A value that was never seen answers NXDOMAIN, which is both the DNSBL idiom and
what lets resolvers cache the negative. A value that was seen answers with a
`127.0.0.x` address whose last octet gives the order of magnitude: `1` is once,
`2` is single digits, `3` is tens, and so on up to `9`. A client that only
checks "did I get an address at all" works unchanged.

Three ways of spelling a value in the query name are supported, chosen per
namespace in the configuration:

	ip      4.3.2.1.malware.sdb.example.com    ->  1.2.3.4
	        (reversed octets, as RBLs do; IPv6 uses the ip6.arpa nibble form)
	domain  evil.com.domains.sdb.example.com   ->  evil.com
	base32  <base32 of the value>.hashes.sdb.example.com

TCP is supported, and a reply too large for a datagram comes back truncated so
the client retries over it.

### Before you enable it

**DNS has no authentication.** The `[acl]` section does not apply, so anything
reachable over DNS is readable by anyone who can send a packet. Accordingly:

* Only namespaces named under `[dns.namespaces]` answer at all; everything else
  in the database is NXDOMAIN, indistinguishable from a value that was never
  seen. Namespaces beginning with `_` are refused at startup.
* The listener binds to `127.0.0.1` unless you say otherwise.
* Names outside the configured zone are REFUSED rather than answered, so this
  can never act as an open resolver.
* `rate_limit` caps queries per second per source address, dropping rather than
  refusing once a source is over budget — an error reply is still an amplified
  packet. Responses are capped at 1232 bytes even if a client advertises more.
* Shadow sightings are off by default, since over DNS they would be an
  unauthenticated write path.

Management interface
====================

Point a browser at `/_management/` and sign in with an API key holding the
`admin` grant — `changeme` on a fresh install:

	[acl]
	changeme   = "rw, admin"
	feeds-only = "admin, r:feeds"

A namespace is a path, so the interface browses one the way a file manager
browses directories: `feeds` holds `feeds/misp/ips`, and a path can be a folder
and a namespace at once — holding values of its own while other namespaces sit
underneath it. Each level lists what is below it and the values stored at that
path, paged and filterable since a namespace can hold a great many.
`/_management/feeds/ips/` is a direct link to that namespace, so views are
bookmarkable. Ticking **search everywhere** looks through whole namespace names
instead of walking a level at a time.

**New namespace** creates one before it holds anything, nesting as deep as you
like: `misp/ips` under `feeds` creates the whole path. An empty namespace is a
real namespace — it is snapshotted, it survives a restart, and sweeps do not
reclaim it, since only namespaces a sweep *empties* are litter.

**Add values** records one value or a pasted list of them, optionally with a TTL
and the time they were seen. They are counted towards consensus exactly as a
`/w/` write would be; nothing added here is a second class of sighting. Writing
to a namespace that does not exist creates it, as it does everywhere else.

Clicking a value shows what the database knows about it: a histogram of when it
was seen, built from the hourly statistics already kept, and a force-directed
graph of **every namespace holding that value** — the point of consensus made
visible. Colour is the top-level namespace, shape says whether a node is the
value, a folder or a namespace, and size is how often the value was seen there.
Folders on the way down are drawn too, so namespaces sharing a path cluster
together. Click a node to browse to it.

Finding those namespaces is arranged to be cheap: `_all` already knows how many
namespaces hold the value, which gives the search something to stop at,
namespaces already in memory are searched first, and evicted shards are read
back only if that target has not been reached by then.

**Access is two-layered.** The `admin` grant is what reaches the interface at
all; ordinary read grants then decide which namespaces are visible inside it,
and write grants decide what may be created or added to. In the example above,
`feeds-only` signs in but sees only `feeds/*` — everything else answers `404`,
the same as a namespace that does not exist, so browsing cannot be used to
enumerate what is out of reach — and, having no write grant, it cannot create a
namespace or add a value anywhere. The relationship graph obeys the same rule:
it draws only namespaces the key may read, while the consensus figure beside it
still counts every namespace, so a scoped key can tell it is not seeing all of
them without being told their names.

An admin key is required **even when `authenticate = false`**. Turning
authentication off is a decision about the sighting API; it should not hand the
management interface to anyone who can reach the port.

The configuration view is **read-only**: settings are read from the file at
startup, so changing them means editing the file and restarting. The interface
reports what the server is actually doing rather than pretending to edit it.

Charts use [Apache ECharts](https://echarts.apache.org/), vendored into the
binary rather than loaded from a CDN so the interface works on a host with no
internet access. See `assets/README.md`.

Importing
=========

ZeroMQ
------

SightingDB can subscribe to a ZeroMQ publisher and record what it hears. The
usual source is MISP, whose publisher sends `<topic> <json>` frames:

	[zmq]
	endpoint = "tcp://misp.example.com:50000"
	topics = ["misp_json_attribute", "misp_json"]
	format = "misp"
	require_to_ids = true

	[zmq.types]
	ip-src = "misp/ips"
	domain = "misp/domains"
	md5 = "misp/hashes"

Attributes are read from `misp_json_attribute`, and from whole events on
`misp_json` including attributes nested inside objects. Only mapped types are
ingested unless `default_namespace` is set, MISP's own timestamps are preserved,
and `require_to_ids=true` limits ingest to attributes MISP flagged as
actionable. A publisher that goes away is retried rather than being fatal.

`format=native` instead reads `{"items":[{"namespace":..,"value":..}]}`, for
publishers that speak SightingDB directly. Note that in this mode the publisher
chooses its own namespaces, so only subscribe to a source you trust — the
`_config` tree is refused, but nothing else is.

This uses a native Rust ZeroMQ implementation, so the release binaries stay
self-contained; it interoperates with libzmq publishers like MISP's.

STIX 2.1
--------

	$ sightingdb -c /etc/sightingdb/sightingdb.toml --import-stix bundles/

Reads one file or every `.json` in a directory, then exits. Three kinds of
object are understood:

* `observed-data` — `number_observed` observations between `first_observed` and
  `last_observed`, following `object_refs` (and the deprecated embedded
  `objects`).
* `sighting` — its `count` and `first_seen`/`last_seen`, resolving
  `sighting_of_ref` and `observed_data_refs`.
* `indicator` — the literal values in its STIX pattern.

Counts and windows survive the import: an observed-data seen 12 times between
two instants becomes a value with `count=12` whose `first_seen` and `last_seen`
bracket that window. A file object yields one sighting per hash. A bundle that
fails to parse is reported and skipped so the rest of the import continues.

Access control
==============

API keys and what each may reach are declared in an `[acl]` section:

	[acl]
	admin     = "rw, admin"
	analyst   = "r"
	feed-misp = "rw:feeds/misp"
	mixed     = "r, w:staging"

Each entry is `<apikey> = <grant>[, <grant>...]`. A grant is `r`, `w` or `rw`,
optionally scoped with `:<namespace prefix>`; without a prefix it covers every
namespace. A key's grants are unioned, and anything not granted is denied.

Prefixes match **whole path segments**, so `rw:feeds/misp` covers
`feeds/misp` and `feeds/misp/ips` but not `feeds/misp-internal` or `feeds`.

A refusal is always `403` with the same body whether the key is unknown or
merely out of scope, so that probing cannot tell valid keys from invalid ones.

`-k <key>` still overrides everything with a single full-access key, replacing
the built-in `changeme`.

Keys are stored in the configuration in the clear. Keep that file readable only
by the user the daemon runs as, and serve over TLS.

### Upgrading

Older versions kept API keys in the database and gave every key full access to
everything. If the configuration has no `[acl]` section, keys restored from a
snapshot keep exactly that access, so upgrading does not lock out a running
deployment — the daemon logs a warning telling you to scope them. Adding an
`[acl]` section makes it authoritative, and the keys in the snapshot are then
ignored.

Persistence
===========

The database is written to `<dbdir>/sightingdb.json` every `snapshot_interval`
seconds and once more on a clean shutdown. Snapshots are written to a temporary
file and renamed into place, so a crash mid-write leaves the previous snapshot
intact rather than a truncated one; at most `snapshot_interval` seconds of
writes are at risk.

A snapshot that exists but cannot be parsed is a fatal startup error rather than
a silent fresh start, since starting empty would look like total data loss and
the next save would make it real.

API keys are *not* in the snapshot: they come from the configuration, so
permissions are reviewable and can live in version control.

Tests
=====

	cargo test

`tests/` also holds Python scripts that exercise a running server; they require the SightingDB Python client library.
