# Operations

## Is it alive

```bash
curl -fsS http://localhost:9999/health
```

```json
{"status":"ok","version":"0.7.1","uptime_seconds":864,
 "resident_shards":4,"shards":7,"catching_up":false}
```

No key, which is what makes it usable as a container healthcheck and a load
balancer probe. `resident_shards` against `shards` is how much of the database
is in memory; `catching_up` is true while a node is pulling what it missed.

## Where the data is

Everything lives in memory and is written to `dbdir` as compressed JSON, one
file per top-level namespace, every `snapshot_interval` seconds and once more
on a clean shutdown.

That shape is the reason `dbdir` matters so much: **without it, nothing
survives a restart.** The server will start, work perfectly, and lose
everything when it stops.

A snapshot that exists but cannot be read is fatal at startup rather than
ignored. Starting empty would look like catastrophic data loss, and the next
save would make it real.

Snapshots carry a format version and are migrated forward on load, so an
upgrade reads what the previous version wrote. The migration happens in memory
and lands on disk at the next save.

## What stays in memory

Chapter 4 has the settings; this is what to do with them.

A top-level namespace is the unit. `hot` keeps it in memory, `warm` writes it
out and drops it after `warm_idle` seconds untouched, `cold` drops it at the
next sweep. Evicted data is **read back when it is next used**, so `cold` costs
one load per burst of activity rather than one per operation.

```bash
curl -H 'Authorization: changeme' -X POST http://localhost:9999/_api/tier \
  -H 'Content-Type: application/json' \
  -d '{"namespace":"archive","tier":"warm","warm_idle":86400}'
```

```json
{"shard":"archive","tier":"warm","warm_idle":86400,
 "own_tier":true,"own_warm_idle":true,
 "effect":"'archive' and everything under it is dropped after 86400s untouched"}
```

The reply says the effect out loud, because a change made from a row deep in a
tree is a change to everything beside it. Either field takes `"default"` to
stop overriding.

A rough guide: feeds you enrich against are `hot`; feeds you keep for history
are `warm` with a long window; anything you query a few times a month is
`cold`.

## Expiring data

A `ttl` on a write is how long the value stays visible. The sweep removes what
has expired, every `sweep_interval` seconds, and gives back the consensus those
values were holding.

Shadow sightings — the record of what was searched for — have their own
`shadow_ttl`, 30 days by default, because "what did people look up" is
interesting for a while and not forever.

## What was refused

```bash
curl -H 'Authorization: changeme' \
  'http://localhost:9999/_management/api/rejections'
```

Newest first, from every write path including the ZMQ ingest, which has no
caller of its own to tell. This is the answer to "the feed says it sent fifty
thousand and I have forty-nine thousand".

Bounded and in memory. A record kept to make something visible, not a fact
about the data.

## Certificates

```toml
[daemon]
ssl = true
ssl_cert = "/etc/sightingdb/tls/cert.pem"
ssl_key = "/etc/sightingdb/tls/key.pem"
```

`sightingdb --install-selfsigned-keys` writes a pair at those paths for getting
started. The Configuration page shows the expiry and warns at 30 days.

That warning matters more in a galaxy than it looks: when a certificate lapses,
peers stop being able to authenticate to each other, and a galaxy comes apart
without any one server failing. For a galaxy of self-signed instances — which
is what `--setup` produces — set `verify_tls = false` in `[galaxy]` and
understand what you have chosen.

## Logs

`log_out` and `log_err` in `[daemon]`, or stdout and stderr in a container.
Every line is timestamped, including panics, which is worth knowing because a
crash with no timestamp is hard to line up against anything else.

For more control, `-l` takes a log4rs configuration.

## Backing up

Stop the server, or take the snapshot directory while it runs and accept that
you get the last snapshot rather than the current state — up to
`snapshot_interval` behind. The files are self-contained; copying `dbdir`
copies the database.

The machine-owned files from chapter 4 — `acl.toml`, `tiers.toml`,
`tags.toml`, `peers.toml` — are small, change rarely, and are worth having in
the same backup. The keys in particular: a galaxy whose load balancer has lost
its `peers.toml` has lost the credentials it reaches its nodes with.

## Upgrading

One binary. Stop it, replace it, start it. Snapshots migrate forward on load,
and the configuration you have keeps working — new settings have defaults that
preserve the previous behaviour.

In a galaxy, upgrade the nodes before the routers. A galaxy running mixed
versions is visible on the Galaxy page, which reports each peer's version,
because that is worth seeing before it misbehaves rather than after.

Reload the management interface once after an upgrade if it looks wrong; see
the end of chapter 10.

## Things that have surprised people

**Reads are recorded.** A read without `noshadow` writes a shadow sighting.
Enrichment loops should pass it; an analyst's lookup should not.

**`consensus` counts namespaces, not sightings.** A value seen four thousand
times in one feed has a consensus of one.

**Deleting removes a namespace, not a value.** There is no delete-one-value
route; use a `ttl`.

**`node_id` must be unique in a galaxy.** Two servers sharing one quietly
corrupt the counting, and nothing will tell you.

**A new node needs peers of its own**, or reads hashed to it will miss. See
chapter 9.
