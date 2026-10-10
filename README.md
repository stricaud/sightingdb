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
	    --setup                  Install: directories, configuration, certificate, key, service
	    --installed              List the files this installation uses, and whether each is there
	    --start                  Start the installed service
	    --stop                   Stop it. 
	    --restart                Restart it
	    --erase                  Stop it, remove its service and empty the database
	    --erase-hard             The same, and the configuration, keys and certificate too
	    --install-selfsigned-keys Write a self-signed cert and key, then exit
	    --import-stix <PATH>     Import STIX 2.1 bundles, then exit
	-l, --logging-config <FILE>  log4rs configuration file (default: etc/log4rs.yml)
	-k, --apikey <APIKEY>        Set the default API key, replacing the built-in 'changeme'
	-v, --verbose...             Increase verbosity

What is installed
-----------------

	$ sightingdb --installed
	SightingDB 0.5.7 — the files this installation uses

	  present  configuration    /etc/sightingdb/sightingdb.toml     2.9 KB, mode 0644
	  present  logging config   /etc/sightingdb/log4rs.yml          110 B, mode 0644
	  present  API keys         /etc/sightingdb/acl.toml            265 B, mode 0600  (rewritten when a key is saved)
	  missing  tiers            /etc/sightingdb/tiers.toml            (written when a tier is changed)
	  present  TLS certificate  /etc/sightingdb/ssl/cert.pem        1.2 KB, mode 0644
	  present  TLS key          /etc/sightingdb/ssl/key.pem         1.7 KB, mode 0600
	  present  database         /var/lib/sightingdb                 7 file(s), 4.2 MB
	  present  binary           /usr/local/bin/sightingdb           12.4 MB, mode 0755  (left alone by --erase)
	  present  service          /etc/systemd/system/sightingdb.service  1.6 KB, mode 0644

Paths come from the configuration, so these are the files *this* install reads
and writes, in full — not the ones a default install would use. A missing file
is often normal: the tiers file appears the first time a tier is changed. A key
or certificate that more than its owner can read is called out with the `chmod`
that fixes it.

Starting and stopping
---------------------

	$ sightingdb --stop
	$ sightingdb --start
	$ sightingdb --restart

**`kill` does not stop it, and neither does `kill -9`.** Both service managers
are told to keep it running — the systemd unit has `Restart=on-failure` and the
launchd plist has `KeepAlive` — so the supervisor starts it again the moment it
dies. Stopping means telling the supervisor, which these flags do, and which
differs by platform and by whether the service is the system's or your own:

	systemctl stop sightingdb                 # Linux, system
	systemctl --user stop sightingdb          # Linux, yours
	launchctl bootout system/com.github.stricaud.sightingdb          # macOS, system
	launchctl bootout gui/$(id -u)/com.github.stricaud.sightingdb    # macOS, yours

`--installed` prints the right one for the service it finds. `--restart` uses
`systemctl restart` or launchd's `kickstart -k`, since launchd has no restart
verb of its own.

### It seems to restart every few seconds

Then something else already has the port, and the supervisor is faithfully
restarting the copy that lost:

	INFO sightingdb - Starting Sighting Daemon
	INFO sightingdb - Saving the database to /Users/you/.sightingdb/db
	(ten seconds later, the same again)

The reason is now logged where the rest of it is — `cannot listen on
https://127.0.0.1:9999: something already has that address` — but the usual
cause is **two services installed at once**: an install from before 0.5 used
the launchd label `com.devo.sightingdb`, and `--setup` installs
`com.github.stricaud.sightingdb`. Both run the same binary against the same
configuration, one wins the port, and launchd restarts the other every ten
seconds forever.

`sightingdb --installed` lists every service it finds and says so outright when
there is more than one. To remove an old launchd job:

	launchctl bootout gui/$(id -u)/com.devo.sightingdb
	rm ~/Library/LaunchAgents/com.devo.sightingdb.plist

Removing it again
-----------------

	$ sightingdb --erase        # the service and the database; keeps your settings
	$ sightingdb --erase-hard   # those, and the configuration, keys and certificate

Both list what will go and what will stay, then require the word `erase` typed
in full — not `y`, and there is no flag to skip it. They stop the service, stop
any daemon still running with this configuration, and then remove the files.

| | `--erase` | `--erase-hard` |
| --- | --- | --- |
| snapshots in `dbdir` | removed | removed |
| the service unit | removed | removed |
| `sightingdb.toml` | kept | removed |
| `acl_file`, `tiers_file` | kept | removed |
| TLS certificate and key | kept | removed |
| the binary | kept | kept |

`--erase` is the one to reach for when something is wrong with an installation:
it clears the way for `--setup` to run again, and you keep your API keys, your
certificate and everything you configured. `--erase-hard` is the counterpart of
`--setup` — afterwards nothing of the installation is left.

Both remove **only what this installation owns**. A logging configuration found
in `/etc` or your home directory is the machine's rather than this install's, a
service unit that runs a different configuration belongs to that one, and the
binary is left where it is — all of them named under "And leaves" before you
confirm. In `dbdir` only the snapshot files are removed, and then the directory
if that is all it held; anything else stays, and it says so.

`--setup` refuses to run while a service is installed, for the reason above: two
of them would fight over the port and one would be restarted forever. It says
which flag to use.

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

Pass `tags=<comma,separated>` to record what is known about the value beyond the fact that it was seen:

	$ curl -k 'https://localhost:9999/w/my/namespace/?val=127.0.0.1&tags=stix-type:ipv4-addr,tlp:amber'
	{"message":"ok","count":1}

Tags are *merged*, so one feed contributing `stix-type:ipv4-addr` and another contributing `tlp:amber` leave the value knowing both. See [Tags](#tags).

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

Namespaces whose first path segment begins with `_` are internal: `_all` is the
consensus tally, `_shadow/*` is what was searched for, and `_config` held API
keys on older deployments. The database writes them about itself, and **no
write route can reach them** — `/w`, `/wb`, `/vwb` and `/d` all answer `403`,
whatever the key. A client able to write `_all` could give a value a consensus
no namespace supports.

Reading them stays allowed apart from `_config`, so `/r/_all?val=<value>` is
how you ask what a value's consensus is, and `/r/_shadow/<namespace>` is how
you review searches. The underscore only counts at the front:
`feeds/_private/ips` is an ordinary namespace.

To ask how many values a namespace holds without fetching them:

	$ curl -k 'https://localhost:9999/r/my/namespace/?count'
	{"namespace":"my/namespace","values":3,"exact":true,"paged_in":false}

This is O(1) — the value map already knows its own length. `exact` is `false`
when the namespace has ever held a TTL, because a value stops being visible the
moment it expires but is only removed by the next sweep, leaving the stored
count an upper bound in between. Counting raises no shadow sighting.

Bulk
----
	$ curl -k -X POST https://localhost:9999/wb -H 'Content-Type: application/json' \
	    -d '{"items":[{"namespace":"my/namespace","value":"127.0.0.1"}]}'
	{"message":"ok","written":1,"items":[{"index":0,"namespace":"my/namespace","value":"127.0.0.1","status":"ok","count":1}]}

`timestamp`, `ttl`, `tags` and `noshadow` are optional on each item.

Every item gets its own outcome in `items`, in the order you sent them, so one
bad entry tells you which one it was instead of casting doubt on the batch. A
successful item carries the value's resulting `count` — the same number `/w`
answers with, read under the lock that incremented it, so you do not need a
follow-up read to learn it:

	$ curl -k -X POST https://localhost:9999/wb -H 'Content-Type: application/json' \
	    -d '{"items":[{"namespace":"my/namespace","value":"127.0.0.1"},{"namespace":"my/namespace","value":""}]}'
	{"message":"partial","written":1,"items":[{"index":0,...,"status":"ok","count":2},{"index":1,...,"status":"error","error":"Refusing to write an empty value."}],"errors":[...]}

A failing item does not discard the ones beside it: whatever was accepted is
kept, and `written` counts it. An item your key may not write fails the same
way as any other — its `status` is `error` and the rest of the batch still
lands — so **read `items` rather than the status code** to find out what
happened to a given entry.

The status describes the batch as a whole:

| status | `message` | when |
| ------ | --------- | ---- |
| `200`  | `ok`      | every item landed |
| `200`  | `partial` | some landed, some did not |
| `403`  | `failed`  | nothing landed, and every item was refused |
| `400`  | `failed`  | nothing landed, for reasons that were not all refusals |

### Checking a batch first

`/vwb` is a dry run of `/wb`. It takes the same body and answers what `/wb`
would have answered for it — the same status, the same `message`, the same
`status` and `error` on every item — and records nothing at all:

	$ curl -k -X POST https://localhost:9999/vwb -H 'Content-Type: application/json' \
	    -d '{"items":[{"namespace":"my/namespace","value":"127.0.0.1"},{"namespace":"my/namespace","value":""}]}'
	{"message":"partial","writable":1,"items":[{"index":0,...,"status":"ok"},{"index":1,...,"status":"error","error":"Refusing to write an empty value."}],"errors":[...]}

`writable` rather than `written`, because nothing was. Items carry no `count`
for the same reason. A `message` of `ok` means the same batch sent to `/wb`
would be accepted in full.

Both routes decide each item with the same code, so the dry run cannot drift
into approving something the writer rejects. It is a report, not a reservation:
the ACL can be rewritten between the two calls, so a batch that validates can
still be refused when you write it. `/vwb` is for checking a batch *before* you
commit to it — it does not replace reading the `items` that `/wb` gives back.

It also leaves no trace, which `/wb` cannot: probing with a real write records a
sighting you then have to live with.

### Which values were rejected

Every write path answers its own caller about a value it would not write — but
a caller is not always there to read it, and the ZMQ ingest has no caller at
all. So all of them also record it, and the management interface can be asked
after the fact:

	$ curl -k -H 'Authorization: changeme' \
	    'https://localhost:9999/_management/api/rejections?namespace=feeds&limit=5'
	{"rejections":[{"when":1790263370,"namespace":"feeds/misp/ips","value":"","reason":"Refusing to write an empty value.","source":"ingest"}],"total":1,"capacity":1000}

`source` is which path turned it away: `write` (`/w`), `bulkwrite` (`/wb`),
`management`, or `ingest`. Newest first, filtered to what your key may read.
`DELETE` the same URL to forget them all, which needs an unscoped key.

The record is **bounded and in memory**. Once `total` reaches `capacity` the
oldest entries are being dropped to make room, it does not survive a restart,
and it is deliberately kept out of snapshots, consensus and the STIX export —
a value that was never written has no business appearing there. It is for
working out why a feed is failing, not for audit. Set `rejection_log` in
`[daemon]` to resize it, or to 0 to switch it off.

`/vwb` records nothing here, since it writes nothing — a dry run would
otherwise let anyone flood the record without writing a thing.

The `errors` array predates `items` and is still sent when there are failures;
everything in it also appears in `items`.

Authentication
--------------
	$ curl -H 'Authorization: changeme' -k https://localhost:9999/w/my/namespace/?val=127.0.0.1
	{"message":"ok","count":1}

Authentication is on unless `authenticate=false` is set in the configuration. Keys and their permissions are declared in the `[acl]` section; see below.

**Where to put the key.** Three ways, in the order you should prefer them:

| | | |
| --- | --- | --- |
| `acl_file`, or `[acl]` | best | A file the daemon reads. Nothing else on the host sees it, permissions are the filesystem's, and it is the only one that can carry more than one key with different rights. What the Helm chart uses. |
| `SIGHTINGDB_APIKEY` | acceptable | Replaces the built-in default key, for a container or a first run. Visible to whatever can read `/proc/<pid>/environ`, and to `kubectl describe pod` if set inline rather than from a Secret. |
| `-k <key>` | avoid | The same thing on the command line, where `ps` shows it to every process on the host. The daemon warns when you use it. |

The last two grant one key unrestricted access; scoped grants need the file.

REST Endpoints
==============
	/w: write (GET)
	/wb: write in bulk mode (POST)
	/vwb: check a bulk write without recording it (POST)
	/r: read (GET)
	/rs: read with statistics (GET)
	/rb: read in bulk mode (POST)
	/rbs: read with statistics in bulk mode (POST)
	/d: delete (GET)
	/stix: export a namespace as a STIX 2.1 bundle (GET)
	/_api/stix: export one or more namespaces as STIX 2.1 (POST)
	/_api/tier: set a namespace's tier and idle window (POST)
	/c: configure (GET, not implemented)
	/i: info (GET)
	/health: liveness and readiness, no key required (GET)
	/_api/openapi.yaml: this API as an OpenAPI 3 document (GET)

API reference
=============

[`doc/routes.md`](doc/routes.md) walks every route with a real request and the
response it actually returns, including the error cases and what each status
code means. Start there if you are writing a client by hand.

[`doc/openapi.yaml`](doc/openapi.yaml) describes the whole HTTP API — data,
STIX, storage and management — as an OpenAPI 3.0.3 document. Import it into
Postman (**File → Import**), Insomnia, Bruno or anything else that reads
OpenAPI, and every endpoint arrives with its parameters, example bodies and
responses.

A running instance also serves it, so you can always ask an instance to
describe *itself* rather than trusting a file that may be older:

	$ curl -k https://localhost:9999/_api/openapi.yaml -o sightingdb.yaml

That copy has the version rewritten to whatever the server actually is. Set
the API key once in Postman as a collection-level API-key auth with the header
name `Authorization` and the key as the value — no `Bearer` in front of it —
and every request inherits it.

A test asserts that every route the server registers appears in the document,
so an endpoint added without documentation fails the build rather than being
discovered by whoever imported the collection.

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
	rejection_log     Rejected values kept in memory (default 1000, 0 = off).

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

**Add values** records one value or a pasted list of them, optionally with
[tags](#tags), a TTL and the time they were seen. They are counted towards consensus exactly as a
`/w/` write would be; nothing added here is a second class of sighting. Writing
to a namespace that does not exist creates it, as it does everywhere else.

**Export STIX** downloads the namespace being browsed as a STIX 2.1 bundle; see
[Exporting](#exporting).

Clicking a value shows what the database knows about it: its tags, which can be
edited there and are what the STIX export reads; a histogram of when it was
seen, built from the hourly statistics already kept; and a force-directed graph
of **every namespace holding that value** — the point of consensus made
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

MISP's own tags come across as they are — `tlp:amber` means the same thing here
— alongside `misp-type:`, `misp-category:` and `misp-event:`, and the MISP type
is translated to a `stix-type:` where there is a one-to-one mapping, so the STIX
export can build a pattern without knowing anything about MISP. See
[Tags](#tags).

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

What the bundle says *about* a value is kept as [tags](#tags): the observable
type, the indicator's id and `indicator_types`, TLP markings (by reference to
the well-known ids as well as by definition), `confidence`, the identity that
published it and the identities in `where_sighted_refs`, the name, and
`valid_until`. That is what lets [the export](#stix-21-1) put the value back on
the wire as STIX without inventing the parts a bare value cannot hold.

Tags
====

A sighting on its own is `<namespace, value, count, first_seen, last_seen>`.
That is enough to answer "how often, and when" and nothing else — it does not
say what the value *is*, who saw it, or how it may be shared. Tags carry that,
and are what makes the STIX export able to produce something a consumer can act
on.

A tag set is a **comma-separated list**, each entry either a bare label or
`key:value`:

	stix-type:ipv4-addr, tlp:amber, confidence:80, identity:Beta Cyber Intelligence Company

Comma is the separator because the interesting values contain spaces, so a
value can contain anything *except* a comma — colons included, which is what a
URL or an RFC 3339 timestamp needs. A key may repeat; `indicator-type` below
does. Whitespace around entries is trimmed.

Tags arrive three ways: the importers write what the source said (see
[Importing](#importing)), `tags=` on a write adds to them, and the management
interface edits them by hand. Writes **merge**, so two feeds each contribute
what they know; only the management interface's tag box replaces a set, which
is how a wrong tag comes off.

Vocabulary
----------

These are the keys the STIX export understands. Anything else is kept and
ignored, so your own conventions cost nothing.

| Tag | What it does |
| --- | --- |
| `stix-type:<type>` | The observable type, and so the pattern: `ipv4-addr`, `domain-name`, `url`, `email-addr`, `mutex`, `windows-registry-key`, or `file.<ALGORITHM>` for a hash. Without it the type is taken from the `[stix.types]` mapping for the namespace, and failing that from the shape of the value. |
| `stix-id:indicator--<uuid>` | Reuse this indicator id instead of minting one. Written by the STIX importer, so a value that arrived as STIX goes back out under the id its publisher gave it. |
| `indicator-type:<value>` | Adds to `indicator_types`. Repeatable. The STIX vocabulary is `malicious-activity`, `anomalous-activity`, `benign`, `compromised`, `attribution`, `unknown`, ... |
| `tlp:<white\|green\|amber\|red>` | Marks the indicator and the sighting with the matching TLP marking definition, which is included in the bundle. |
| `confidence:<0-100>` | STIX `confidence` on both objects. Out-of-range values are ignored. |
| `identity:<name>` | Who saw it: becomes an `identity` object referenced from `where_sighted_refs`. Repeatable. Without one, the sighting is attributed to the publishing identity. |
| `name:<text>` | Indicator `name`. |
| `description:<text>` | Indicator `description`. |
| `valid-until:<rfc3339 or unix seconds>` | Indicator `valid_until`. Otherwise a TTL supplies one, counted from the last sighting exactly as the database counts it. |

The importers also write tags that the export does not read but a person might
want: `misp-type:`, `misp-category:`, `misp-event:`, and MISP's own tags as
they were published.

Tags are visible wherever a value is: in `/r` and `/rs` responses, in the DNS
TXT answer, and in the management interface.

Exporting
=========

STIX 2.1
--------

	$ curl -k -H 'Authorization: changeme' https://localhost:9999/stix/feeds/misp/ips

One namespace becomes a STIX 2.1 bundle shaped after the OASIS ["Sighting of an
Indicator"](https://oasis-open.github.io/cti-documentation/examples/sighting-of-an-indicator)
example: for each value an `indicator` carrying the pattern and a `sighting`
pointing at it with the count and the observation window, plus the `identity`
objects they refer to and any TLP markings used.

	{
	  "type": "bundle",
	  "id": "bundle--...",
	  "objects": [
	    {"type": "identity", "id": "identity--...", "name": "SightingDB",
	     "identity_class": "system", ...},
	    {"type": "indicator", "id": "indicator--...",
	     "pattern": "[ipv4-addr:value = '198.51.100.7']", "pattern_type": "stix",
	     "indicator_types": ["malicious-activity"], "confidence": 80,
	     "valid_from": "2020-09-13T12:26:40.000Z", ...},
	    {"type": "sighting", "id": "sighting--...", "count": 12,
	     "first_seen": "2020-09-13T12:26:40.000Z",
	     "last_seen": "2020-09-14T09:03:11.000Z",
	     "sighting_of_ref": "indicator--...",
	     "where_sighted_refs": ["identity--..."],
	     "x_sightingdb_namespace": "feeds/misp/ips", ...}
	  ]
	}

The export is a read, so it answers to the same key and the same permissions as
`/r`. The management interface's **Export STIX** button downloads the bundle for
the namespace being browsed, by calling the same automation endpoint below — so
what the button gives you and what a script gets cannot drift apart.

For automation
--------------

	$ curl -k -X POST https://localhost:9999/_api/stix \
	    -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -d '{"namespaces": ["feeds/misp/ips", "feeds/otx/ips"], "q": "10.0.", "limit": 5000}'

`POST /_api/stix` is the same export for a script: a namespace is a path, so
POST saves encoding it into a URL, and several can be gathered into one bundle.

| Field | |
| --- | --- |
| `namespaces` | The namespaces to export. |
| `namespace` | Shorthand for one, so a one-liner stays a one-liner. |
| `q` | Substring filter over values, as when browsing. |
| `limit` | Values read per namespace: 10,000 by default, 100,000 at most. |

**Every namespace is authorized on its own**, exactly as a bulk read is: naming
one the key may not read refuses the whole request with `403` rather than
quietly returning the half it is allowed. `_config` is refused outright. As
everywhere else on the data API, `authenticate = false` means there is no ACL
to consult — the switch that opens `/r` opens this too.

Because ids are deterministic, gathering namespaces is worth doing: a value in
two of them has **one** indicator between them and a sighting each.

	X-SightingDB-Exported: 3
	X-SightingDB-Skipped: 0
	X-SightingDB-Truncated: false
	X-SightingDB-Missing: feeds/nope

A namespace that does not exist is named in `X-SightingDB-Missing` and the rest
still come back; if none of them exist the answer is `404`.

**Ids are deterministic.** Every id is a UUIDv5 derived from a SightingDB
namespace UUID and the thing it names, which has two consequences worth
relying on: exporting the same data twice produces the same bundle byte for
byte, and the same value in two namespaces produces *one* indicator with a
sighting each — so a consumer merging both bundles sees one indicator sighted
twice rather than two indicators. A `stix-id:` tag overrides the minted id.

Who the bundle is published as comes from the configuration:

	[stix]
	identity = "Alpha Threat Analysis Org."
	identity_class = "organization"

The default is `SightingDB` with class `system` — a database reporting what it
saw. That identity is the `created_by_ref` of everything in the bundle, and the
`where_sighted_refs` of any sighting whose value carries no `identity:` tag.

**A value with no observable type is skipped**, because a STIX indicator is a
pattern and there is no pattern without a type. The response says how many that
was, rather than leaving it to be noticed:

	X-SightingDB-Exported: 412
	X-SightingDB-Skipped: 3
	X-SightingDB-Untyped: 0
	X-SightingDB-Truncated: false

Tag those values with `stix-type:`, or map the namespace in `[stix.types]` so
the whole namespace has a type. The management interface has a Tags column on
the values list for this, and an Observable column beside it showing which
values currently have none.

`limit=` caps how many values one export reads (10,000 by default, 100,000 at
most); `X-SightingDB-Truncated` says when the namespace held more.

### Exporting a subtree

An export covers the one namespace named. Add `recursive` — `?recursive` on
`GET /stix/<namespace>`, or `"recursive": true` in the `POST /_api/stix` body —
to take every namespace below it as well, in one bundle. The management
interface offers it as a checkbox when you press **Export STIX**.

	X-SightingDB-Namespaces: 4
	X-SightingDB-Exported: 412

"Below" matches whole path segments, so `feeds` covers `feeds` itself and
`feeds/misp/ips`, and never `feeds-internal` — a different namespace, not a
child. The namespace you name is authorized as always, so asking for a subtree
your key may not read is refused; a namespace *found* underneath that it may
not read is left out instead, exactly as it is absent from the namespace tree.

`limit=` is the budget for the whole export rather than for each namespace in
it, so a recursive export of a large tree reads what you asked for and no more.
`X-SightingDB-Truncated` says when the budget ran out with more to give.

Note that this changes `limit=` for an existing caller that named several
namespaces in one `POST /_api/stix`: the limit used to apply to each. Naming a
single namespace is unaffected.

### Exporting everything anyway

To take the whole namespace regardless, add `untyped=include` — `?untyped=include`
on `GET /stix/<namespace>`, or `"untyped": "include"` in the `POST /_api/stix`
body. The management interface asks which you want when you press **Export
STIX**.

Values nothing could identify then go out as the custom observable
`x-sightingdb-value`, each indicator carrying `x_sightingdb_untyped: true`:

	{"type":"indicator","pattern":"[x-sightingdb-value:value = 'whatever this is']",
	 "pattern_type":"stix","x_sightingdb_untyped":true, ...}

	X-SightingDB-Exported: 415
	X-SightingDB-Skipped: 0
	X-SightingDB-Untyped: 3

STIX 2.1 has no plain-text observable, and the specification requires a custom
type to carry an `x-` prefix, so this is our own rather than a standard one.
Naming it rather than borrowing something close — `artifact`, say — is what
keeps the bundle honest: a consumer is told this is a value SightingDB could
not classify, instead of being handed a pattern that claims something false
about it. Filter on `x_sightingdb_untyped` rather than on the type name.

A value carrying `stix-type:` explicitly is never counted as untyped, even
where that type is `x-sightingdb-value`: someone said what it was on purpose.
Skipping stays the default, so an existing export does not change shape.

Round trip
----------

Importing a bundle and exporting it again preserves what both formats can hold:
the importer writes the observable type, the indicator id, its `indicator_types`,
markings, confidence, the identities and the validity window as tags, and the
exporter reads them back. See [Tags](#tags).

Counts survive too. A bundle that pairs an indicator with a sighting of it —
which is what this export produces — is read as *one* observation of the
sighting's count, not as the sighting plus the indicator again. An indicator
nothing points at is still an observation of its own.

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

**A refusal is logged.** The client is told `403`; the server logs which
address asked, what it asked to do, to which namespace, and a short fingerprint
of the key — never the key itself, since a log is copied and read by more
people than a credential should be. Unlike the answer to the client, the log
distinguishes a key that does not exist from one that exists but is not allowed
there: hiding that from a caller stops it probing, while telling the operator
is the whole point.

	WARN sightingdb::handlers - Refused 10.0.0.9:5000: no such key c211eb3e, asked to write 'feeds/ips'
	WARN sightingdb::handlers - Refused 10.0.0.9:5000: key 4f2a91bd may not read 'private'

A request with no key at all is logged at debug, since on an open port that is
ordinary noise.

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

Keeping it in memory, or not
----------------------------

Storage is one file per **top-level namespace** — a shard — so `feeds/misp/ips`
and `feeds/otx/domains` live in `feeds`, and a shard is paged in and out as a
unit. Which is why the settings below belong to the shard and cover everything
under it: there is no finer setting because there is no finer eviction.

	[storage]
	default_tier = "hot"
	warm_idle = 3600
	tiers_file = "tiers.toml"

	[storage.tiers]
	archive = "cold"
	feeds = { tier = "warm", warm_idle = 86400 }
	staging = { warm_idle = 300 }

| Tier | |
| --- | --- |
| `hot` | Never evicted. |
| `warm` | Written out and dropped once untouched for `warm_idle` seconds. |
| `cold` | Dropped at the next sweep once idle. |

`warm_idle` is how long "untouched" means, and an entry may set it for one shard
rather than taking the global one — a feed worth keeping for a day and a staging
tree worth keeping for five minutes are both warm, on different windows. An
entry may also set the window alone, leaving the tier to `default_tier`.

Evicted data is not gone: the shard is read back when it is next used, so
`cold` costs one load per burst of activity rather than one per operation.

**Changing it while it runs.** Both halves are editable from the management
interface — a tier control and, for a warm shard, the number of seconds beside
it — and over HTTP for automation:

	$ curl -k -X POST https://localhost:9999/_api/tier \
	    -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -d '{"namespace": "feeds/misp/ips", "tier": "warm", "warm_idle": 86400}'
	{"shard":"feeds","tier":"warm","warm_idle":86400,"own_tier":true,"own_warm_idle":true,
	 "effect":"'feeds' and everything under it is dropped after 86400s untouched"}

Name any namespace and the setting lands on its shard, which the reply says out
loud: a change made from a row deep in a tree is a change to everything beside
it. Either field takes `"default"` to stop overriding and go back to
`[storage]`, and a change is written to `tiers_file` so it survives a restart.

Certificate expiry
------------------

A server serving TLS reports when its certificate runs out, and says so loudly
before it does — at startup, in the log, and in the management interface:

	WARN sightingdb::tls - The TLS certificate /etc/sightingdb/ssl/cert.pem
	expires in 10 day(s). Replace it before then.

**Configuration** shows it with the days remaining, amber under 30 days and red
once expired. Thirty days is the line: long enough to notice, order and install
a replacement without hurrying.

	"tls": {"cert": "/etc/sightingdb/ssl/cert.pem",
	        "not_after": 1792530174, "days_left": 10}

`/_management/api/info` reports `not_after` as an absolute moment rather than a
countdown, so the answer cannot go stale between being sent and being read; the
page works out "soon" from the same threshold the server logs at, so the two
cannot disagree.

A certificate made by `--setup` is good for a year, so this starts mattering
about eleven months in — which is exactly when nobody is thinking about it.

Setting one up
--------------

`sightingdb --setup` asks how the server should run before anything else:

	How should this server run?
	  1) standalone          stores everything, no other servers (the usual answer)
	  2) node in a galaxy    stores namespaces; other servers forward to it
	  3) router              stores nothing of its own; forwards to its peers
	  4) node and router     stores some namespaces and forwards the rest

Standalone is the usual answer, and the three others are the shapes a galaxy is
built from. For anything but standalone it also asks which namespaces the server
stores, and for a name — unique in the galaxy, defaulting to the hostname,
because two servers sharing a name would each take the other's contribution for
their own.

The configuration it writes is commented throughout, so the file is where you go
to change your mind rather than somewhere to look settings up from. For a
forwarding mode it includes a `[galaxy]` template, **commented out**: a peer's
key comes from that peer's own ACL, which does not exist until that peer has
been set up. So install the other servers first, create a key on each for this
one, then fill it in and restart. Until then the server has no peers and
reports itself as a plain node, which is what it is.

What a server stores
--------------------

By default a server stores every namespace, which is what a standalone one
wants. `namespaces` in `[storage]` narrows it:

	[storage]
	namespaces = ["/"]                  # everything, said explicitly (the default)
	#namespaces = ["feeds", "threats"]  # those subtrees and nothing else
	#namespaces = []                    # nothing of its own: a pure router

Prefixes match whole path segments, so `feeds` holds `feeds/misp/ips` and never
`feeds-internal`. The internal namespaces — `_all`, `_shadow/*`, `_config` — are
always held whatever this says, because a server cannot keep its own consensus
tally otherwise; listing one is an error.

A write to a namespace the server does not store is refused with **421
Misdirected Request**: the request arrived somewhere that cannot serve it,
which is neither forbidden nor missing and needs to stay distinguishable from
both. Reads of a namespace it does not hold are `404`, as they already were.

	$ curl -k 'https://localhost:9999/w/other?val=1.2.3.4'
	{"message":"This server does not store 'other'. Its [storage] namespaces list
	  says what it holds."}                                               # 421

Counting, and node identity
---------------------------

A sighting is counted **per server**, not as one running total. The stored
shape is a map from node id to count, and what a client is given is the sum —
so nothing a reader sees changes.

The reason is that an increment is not idempotent. `/w` means "add one", so any
sync that read a peer and wrote back what it found would double the count, and
double it again on the next round. Keeping each server's contribution separate
makes merging two copies a union of disjoint entries: applying the same merge
twice changes nothing, which is what makes replication safe to retry.

	[daemon]
	node_id = "local"

`local` is right until the server joins a galaxy. Then give each one its own
name — two sharing an id would each take the other's contribution for their own,
and a merge would lose one of them. Letters, digits, `-`, `_` and `.`, up to 64
characters.

Changing it later is safe but not free: the old name keeps its contribution in
the stored data and the new one starts from zero, so the total is unchanged
while the attribution splits in two.

Hourly statistics are kept the same way and reported merged, so `/rs` shows one
bucket per hour however many servers contributed to it. `stats_retention` is
counted within each server's own buckets, since retention means "how far back
this server remembers" rather than something to be shared out.

### Upgrading

The snapshot format is version 2. A version 1 database — one total per value —
**opens and is migrated on load**: the totals become the reading server's own
contribution, which is the only thing they can be, and the file is rewritten in
the new shape on the next save. Nothing to do by hand.

	INFO  ...feeds-eacacfab.json.zst is version 1; migrating to version 2 on load

A snapshot from a *newer* build is refused rather than rewritten, so a
downgrade cannot quietly drop fields it does not know about.

### Syncing between servers

`POST /_api/merge` folds a peer's copy of a value into this server's. It is not
a sighting — nothing is counted — and every field combines by a rule that
ignores order and repetition, so the same merge can be sent twice and two peers'
copies can arrive either way round:

	counts      the greater of the two, per server
	stats       the same, per hourly bucket
	first_seen  the earlier          last_seen   the later
	tags        the union
	ttl         the shortest non-zero one, zero meaning never

Read what to send with `?for_merge`, which answers in exactly the shape the
merge route takes:

	$ curl -k 'https://localhost:9999/r/feeds/ips?val=1.2.3.4&noshadow&for_merge'
	{"counts":{"node-a":3},"stats":{"node-a":{"1791658800":3}},
	 "first_seen":1791660347,"last_seen":1791660347,"tags":"","ttl":0}

The counts are **per server**, which is the whole point: offering a total would
make the receiver attribute every server's sightings to the sender, and two
servers exchanging totals inflate each other without bound.

An entry naming the receiving server is ignored and reported in
`ignored_self` — a peer does not get to say what this server has seen.

Merging is authorized as a write, so a peer's key bounds what it may merge
exactly as it bounds what it may write.

`changed: false` on an item means the local copy already held everything
offered. That is a success: during catch-up it is how a caller learns it has
converged.

Galaxy
------

`[galaxy]` lists the other servers this one knows about:

	[galaxy]
	max_hops = 4
	peers = [
	  { url = "https://node-a.example:9999", key = "..." },
	  { url = "https://node-b.example:9999", key = "..." },
	]

**Nothing is forwarded yet.** At this stage the peers are parsed, validated and
reported — `/_management/api/info` carries a `role` object describing what this
server stores and who it knows — so that a topology can be described before it
can be used.

Each peer carries the key this server authenticates to it with, and **that key
is the bound on what this server may do there**. A key granted `rw:feeds` on the
peer cannot write anywhere else, however this server is configured or
compromised, because the peer's own ACL decides. Give each one the narrowest
grant that does the job.

`max_hops` is what stops a miswired cascade: a cycle inflates every count that
travels round it, so it is a limit rather than a tuning knob. A peer may itself
have peers, so a router in front of routers is allowed.

### Forwarding

A server that does not store a namespace passes the request to the peers that
do, so a client talks only to the entry point and never needs to know the
topology.

	peers = [
	  { url = "https://node-a:9999", key = "..." },
	  { url = "https://node-b:9999", key = "...", namespaces = ["feeds"] },
	]

`namespaces` on a peer says what it holds — absent means a full mirror. It is
declared here rather than asked of the peer, because discovery would need the
peer key to carry an `admin` grant and the point of that key is to be the
narrowest thing that works. The cost is that it must agree with the peer's own
`[storage] namespaces`.

**Writes fan out** to every live mirror of the namespace. **Reads go to one**,
chosen by hashing the value over the mirrors, so the same value is always read
from the same place while the mirror set is unchanged — without that, two
consecutive reads could be served by mirrors at different stages of catching up
and show a count going *down*.

A mirror being down does not fail a write: the mirror that took it is what the
others catch up from. What is refused is a write that reached no mirror at all.

	$ curl -k 'https://lb:9999/w/feeds/ips?val=1.2.3.4'   # lb stores nothing
	{"message":"ok","count":1,"new":true}

Answers carry `X-SightingDB-Forwarded: 1`. A request for a namespace nowhere in
reach is `421`; a cascade wired in a loop is `508`, caught by `max_hops`.

**A forwarded write is counted for the server it came from**, not for each
mirror that stores it. Without that, one write fanned out to two mirrors is
counted twice over and merging them adds the two together — three writes
through a load balancer became six once the mirrors synced. The origin travels
in `X-SightingDB-Origin` and is passed along unchanged, so the attribution is
the entry point the client actually talked to.

### Catching up

A server that was down comes back, finds it is behind, and fills in from a peer
that was up — on a timer, with nobody touching it.

	[galaxy]
	sync_interval = 300     # seconds between passes; 0 switches it off

Each pass asks every peer which namespaces it holds, keeps the ones this server
stores, and walks `/r/<namespace>?for_merge` in pages, applying each in place.
Namespaces created while this server was away are found too, through
`/_api/namespaces` — which exists for that and nothing else.

The first pass after startup is a full one, because a server that has just
started has no idea what it missed. Later passes use `?count` as a trigger and
skip a namespace whose peer holds no more values than this one — O(1) on both
sides, which is what makes it usable on a timer. That is a heuristic rather
than a proof: equal counts do not mean equal contents. The full pass on startup
is what stops it being load-bearing.

**While a server is catching up it says so**, in `catching_up` on `/health`. A
router reads that and sends reads to a mirror that is current instead, because
one still catching up would under-report. Writes go to it throughout: they land
directly, and the pass fills in the history behind them. Withholding writes
instead would mean the target keeps moving and a pass under load would never
provably finish.

If every mirror is catching up, one answers anyway. An under-reported count
beats no answer, and refusing would make a whole galaxy unreadable for as long
as it took to start.

	nb down      1.2.3.4=3/-  9.9.9.9=4/-  7.7.7.7=2/-
	+3s          1.2.3.4=3/3  9.9.9.9=4/4  7.7.7.7=2/2

### Searches are recorded where the client is

A read through a router records its shadow sighting **on the router**, and the
forwarded read carries `noshadow` so the mirror serving it records nothing. A
search is then counted once, where the client actually was, instead of once on
whichever mirror happened to answer:

	five reads through a router
	  shadow on the router  5
	  shadow on node-a      0
	  shadow on node-b      0

That also means a read costs the mirrors no write at all, which is what keeps
serving more clients from multiplying write load across a galaxy.

### Consensus across a galaxy

A server in front of a galaxy keeps the galaxy-wide tally, because it sees the
*logical* write — one namespace, one value — while mirroring is a detail below
it. Read it back with `/r/_all?val=<value>`, which is an ordinary namespace read
and needs no endpoint of its own.

	1.2.3.4 written into alpha/one, alpha/two (node-a) and beta/one (node-b)
	  router 3   node-a 2   node-b 1     only the router is right

It is kept by counting forwarded writes the mirrors report as `new`, so it only
ever rises: values expire and namespaces are deleted on the nodes, consensus is
released there, and neither reaches anything in front of them.

	[galaxy]
	reconcile_interval = 3600   # seconds; 0 switches it off

So it is rebuilt on a timer by surveying the galaxy — for each namespace, which
values it holds — and taking consensus to be the number of *namespaces* holding
each value. A set rather than a sum, because the same namespace mirrored three
times is still one namespace.

This walks the galaxy, which is why it has its own long interval. It is a
repair; the incremental tally answers reads in between, and a pass that finds
nothing wrong logs nothing.

### Keys are gossiped, not shared

`acl_file` is rewritten by whichever server served the management request, so
saving a key on one would otherwise leave the others ignorant of it. A change is
now passed on to the peers through **each peer's own management interface** —
which means the peer's ACL decides whether to accept it.

That is what makes this safe without a shared file: a server can only
administer a peer it holds an `admin` key for. A server holding a narrow
`rw:feeds` key there cannot change anything, so gossip flows from whoever holds
the credentials towards the servers they administer, and a narrowly-scoped peer
cannot push back.

	save 'analyst' on the router
	  router  [analyst, changeme]
	  node-a  [analyst, changeme, lb-admin]   took it
	  node-b  [changeme, lb-narrow]           not ours to administer

Safe to repeat: saving a key *sets* its grants rather than adding to them. A
change is pushed as it happens, and this server's keys are offered again every
`gossip_interval` (600s by default; 0 switches the periodic offer off) so a
peer that was down for a change picks it up.

> **A revocation made while a server was offline does not reach it.**
>
> The periodic offer is deliberately additive — it never deletes a key a peer
> has and this server does not, because this server is not necessarily the only
> place keys are managed, and a timer that quietly revoked a key added elsewhere
> would be worse than one that failed to propagate a deletion.
>
> So a key revoked while a peer was down **stays live on that peer**. Repeat the
> revocation once it is back.
>
> The management interface points this out rather than leaving you to find it:
> the **Keys** page shows a "Keys across the galaxy" panel listing, per peer,
> which keys this server revoked that the peer still accepts. It appears only
> when there is something to say.

	revoked_but_present  ["doomed"]      <- revoked here, still live there
	only_on_peer         ["lb-admin"]    <- the peer's own keys; ordinary
	missing              []              <- not sent yet; the offer fixes it

`only_on_peer` is kept separate on purpose. A peer has keys of its own —
including the one this server authenticates with — and reporting those as stale
revocations would make the panel cry wolf every time it was opened.

The record of revocations is held in memory, so it is lost on restart: after
one, a revocation that never landed moves from `revoked_but_present` into
`only_on_peer` and stops being flagged. Checking the peer's own key list is then
the way to find it.

Tier changes travel the same way and under the same rule. A tier has no
"unset" — only a different value — so unlike a key it has no deletion to miss,
and offering what this server holds leaves a peer with exactly that.

### One place to manage keys

The additive offer above cannot carry a revocation to a server that was
offline. If you want one, a server can be declared the owner of the galaxy's
keys:

	# on the server that owns them
	[galaxy]
	acl_authority = true

	# on each server that accepts them
	[galaxy]
	acl_replaceable = true

The owner then offers its **whole** list, to be held exactly, which does remove.
Both ends must agree: a server with `acl_replaceable` off keeps its own keys and
the offer falls back to being additive, so nothing is lost by not opting in.
Setting both on one server is refused at startup — they would take turns
overwriting each other.

Two guards on a replace, the same shape as on a single-key change: the set must
contain an admin key, and it must contain the key making the request, or the
server doing the replacing locks itself out of the one it just took over.

### Seeing the galaxy

`GET /_management/api/galaxy` walks the peers, so one request describes a whole
cascade: this server, its peers with their health, and each peer's own answer
under `below`. The management interface draws it under **Galaxy** — routers as
diamonds, full mirrors and partial mirrors in different colours, and red kept
for a server that is not answering.

Misconfiguration is refused at startup rather than at the first forward — a
peer without a key, a url without a scheme, the same peer listed twice, or
`max_hops = 0`.

The `role` object reports which of the three a server is:

	$ curl -k -H 'Authorization: changeme' https://localhost:9999/_management/api/info
	{..., "role": {"kind": "router", "mirrors_everything": false,
	       "namespaces": [], "peers": ["https://node-a:9999"], "max_hops": 3}}

`kind` is `node` (stores namespaces, forwards nothing), `router` (stores none of
its own, exists to forward) or `both`. It describes a configuration, not a type:
any server can be any of them. Peer **keys are never in the response** — they
are credentials.
It needs write access to the namespace, and a configured `tiers_file` — without
one the tiers are whatever the configuration says and cannot be changed here.

Containers and Kubernetes
=========================

	$ make            # what every target does
	$ make deploy     # into the cluster kubectl already points at
	$ make dev        # into a kind cluster this creates for the purpose

Both build a container image from the source in your working tree, install the
Helm chart, wait for the pod and then write a sighting through it to prove it
works. The difference is the cluster:

* **`make deploy`** uses whatever `kubectl config current-context` names —
  Docker Desktop, Rancher Desktop, minikube, k3d, or a kind cluster you made
  yourself. It hands the image over the way that cluster expects: `kind load`,
  `k3d image import`, `minikube image load`, or — for current Docker Desktop,
  whose node is a container of its own rather than a user of this machine's
  image store — `docker save` piped into the node's containerd. `make load`
  does only that step.
* **`make dev`** creates a kind cluster named `sightingdb` first, and
  `make teardown` deletes it and everything in it.

Then `make port-forward` and `make admin-key` get you into the management
interface, and `make uninstall` removes the release.

**These targets refuse to touch a cluster that is not local.** They install,
delete and write data, so they check the context against a list of local ones
(`docker-desktop`, `rancher-desktop`, `minikube`, `colima`, `kind-*`, `k3d-*`,
`k3s-*`) and stop if it is anything else — a `kubectl config use-context` away
from production should not be one keystroke away from `make deploy`. The
context is resolved once and passed explicitly to every helm and kubectl call,
so nothing can be redirected midway. `ALLOW_ANY_CONTEXT=1` overrides it
deliberately, and `CONTEXT=<name>` picks one without switching your current
context.

A cluster that is not local — one that has to *pull* the image — needs it in a
registry it can reach:

	$ make image-push IMAGE=registry.example.com/sightingdb TAG=0.5.6
	$ helm upgrade --install sightingdb ./helm/sightingdb \
	    --set image.repository=registry.example.com/sightingdb --set image.tag=0.5.6

Docker
------

	$ docker build -f docker/Dockerfile -t sightingdb:dev .
	$ docker run --rm -p 9999:9999 -v sightingdb:/var/lib/sightingdb \
	    -e SIGHTINGDB_APIKEY=$(openssl rand -hex 20) sightingdb:dev

`SIGHTINGDB_APIKEY` replaces the built-in default key. The daemon reads the
variable itself rather than the entrypoint turning it into `-k`, so the key
does not appear in `ps`. For more than one key, or for keys with scoped grants,
mount an `acl_file` — see [Authentication](#authentication).

The image builds this working tree — not a clone of the repository — in a
builder stage and ships the binary on `debian-slim`. Mount a volume at
`/var/lib/sightingdb`: without one the database lives only as long as the
container. TLS is off in the baked-in configuration, because a certificate
built into an image is the same certificate for everyone who pulls it;
terminate TLS in front of it, or mount a key and certificate and set `ssl`,
`ssl_cert` and `ssl_key`.

**It never runs as root.** The image creates a `sightingdb` user and group at
uid/gid 10001 and starts the daemon as that user, the same way the systemd unit
does with `User=sightingdb`. SightingDB has no privilege-dropping code and needs
none: nothing it opens requires root, so there is no window where it is root and
nothing to get wrong in the dropping. The one exception is a port below 1024 —
the DNS listener on 53 — and that is a capability rather than a reason to start
as root:

	$ docker run --cap-add NET_BIND_SERVICE ...        # or publish 53:5353

Two consequences worth knowing. A **bind mount** from the host arrives owned by
whoever owns it on the host, so it has to be writable by uid 10001
(`chown 10001:10001 ./data`) — a named volume inherits the image's ownership and
needs nothing. And because the data directory is owned by group 0 and is
group-writable, the image also works where the uid is assigned rather than
chosen, as on OpenShift.

Helm
----

The chart is in [`helm/sightingdb`](helm/sightingdb), with its own
[README](helm/sightingdb/README.md). Every option in
[`etc/sightingdb.toml`](etc/sightingdb.toml) has a value, and the configuration
file is rendered from them:

	helm install sightingdb ./helm/sightingdb \
	  --namespace sightingdb --create-namespace \
	  --set image.repository=ghcr.io/you/sightingdb --set image.tag=0.5.5

Worth knowing before you deploy it:

* **One pod.** SightingDB holds its data in memory and snapshots it to one
  directory, so a second replica would be a second, unrelated database — the
  chart is a StatefulSet of one and has no `replicaCount`. Scale by giving the
  pod more memory.
* **The admin key lives in a Secret.** `acl.keys` renders an `acl.toml` into
  `<release>-acl`, alongside an `admin-key` entry holding the first key with the
  `admin` grant — `make admin-key`, or:

		kubectl -n sightingdb get secret sightingdb-acl -o jsonpath='{.data.admin-key}' | base64 -d

  Leave `acl.keys` empty and one is generated on install and kept across
  upgrades, so no known key is ever shipped.
* **Keys are seeded, not managed.** An init container copies that `acl.toml`
  onto the data volume, because the management interface rewrites the file and a
  mounted Secret is read-only. Keys created in the interface therefore live on
  the volume and survive upgrades; they are not written back into the Secret.
* **Namespaces can be created up front.** `bootstrap.namespaces` creates them
  through the management API after install and upgrade, so a deployment starts
  with the structure its writers and ACL prefixes assume rather than with
  nothing until the first write.
* **`/health` is the probe.** It needs no API key whatever `authenticate` is
  set to, and reports the version, uptime and how many shards are in memory.
  There is no separate readiness path: the snapshot is restored before the
  listener is bound, so an answer at all means the database is up.

Tests
=====

	cargo test

`tests/` also holds Python scripts that exercise a running server; they require the SightingDB Python client library.
