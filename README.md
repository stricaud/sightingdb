<p align="center"><img src="doc/sightingdb-logo3_128.png"/></p>

SightingDB is a database designed for Sightings, a technique to count items. This is helpful for Threat Intelligence as Sightings allow
to enrich indicators or attributes with Observations, rather than Reputation.

Simply speaking, by pushing data to SightingDB, you will get the first time it was observed, the last time, its count.

However, it will also provide the following features:
* Keep track of how many times something was searched
* Keep track of the hourly statistics per item
* Get the consensus for each item (how many namespaces contain the same value)
* Expire data with a per-value TTL

SightingDB is designed to scale writing and reading. There is no global lock: namespaces are locked independently, and within a namespace each value has its own lock, so concurrent writes to different values never contend.

The database is held in memory and snapshotted to disk (see `dbdir` below). Set no `dbdir` to run purely in memory.

Building
========

1) Make sure you have Rust and Cargo installed. The toolchain is pinned in `rust-toolchain.toml`; rustup will fetch it automatically.
2) Run `make` (or `cargo build`).

You will need OpenSSL development headers to build (`libssl-dev` on Debian/Ubuntu, `openssl` from Homebrew on macOS).

Running
=======

To run from the source directory:

1. Generate a certificate: `cd etc; mkdir -p ssl; cd ssl; openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout key.pem -out cert.pem; cd ../..`
2. `ln -s etc/ssl ssl`
3. Start the daemon: `./target/debug/sightingdb -c etc/sightingdb.conf`

Without `-c`, the configuration is looked up in `/etc/sightingdb/sightingdb.conf` and then `~/.sightingdb/sightingdb.conf`.

Set `ssl=false` in the configuration to serve plain HTTP instead.

Options
-------

	-c, --config <FILE>          Configuration file (default: see above)
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

Authentication is on unless `authenticate=false` is set in the configuration. Any registered key currently grants full access to every namespace; per-namespace permissions are not implemented yet.

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

Beyond the listen address and TLS settings, `[daemon]` accepts:

	dbdir             Directory for snapshots. Unset or blank runs in memory only.
	snapshot_interval Seconds between snapshots (default 300). 0 saves only on shutdown.
	sweep_interval    Seconds between eviction sweeps (default 60). 0 disables the sweeper.
	stats_retention   Hourly statistics buckets kept per value (default 0 = unlimited).
	shadow_ttl        Seconds a shadow sighting is kept (default 0 = forever).

The retention settings default to keeping everything, so upgrading an existing
install never starts discarding data on its own. The configuration shipped in
`etc/sightingdb.conf` sets 30-day windows for both, which is what bounds memory
growth — without them, statistics accumulate one bucket per hour per value and
`_shadow/*` grows for every distinct search, forever.

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

API keys live in the database, so they are part of the snapshot and survive a
restart. `-k` still applies on top of whatever was restored.

Tests
=====

	cargo test

`tests/` also holds Python scripts that exercise a running server; they require the SightingDB Python client library.
