# Running a galaxy

Chapter 8 was what the pieces are. This is building one, changing it, and
taking parts of it out of service.

## Build one in four containers

The fastest way to see all of it:

```bash
docker compose -f doc/docker/docker-compose.yml up --build
```

A load balancer on 9999 and three nodes on 9991–9993, two full mirrors and one
holding a single namespace, loaded with real indicators from CIRCL's public
OSINT feed. `doc/docker/README.md` lists things to try. The rest of this
chapter is what it is doing.

## Adding a node

A load balancer takes a new node over HTTP, and starts using it at once — no
restart, which matters because restarting a router is a gap in service for
everything behind it.

**First, on the new node**, create the key the load balancer will use. It is
the node's own ACL that decides what that key opens, so make it the narrowest
thing that works:

```bash
curl -H 'Authorization: <node admin key>' \
  -X POST https://new-node.example:9999/_management/api/keys \
  -H 'Content-Type: application/json' \
  -d '{"key": "lb-to-new-node", "admin": false,
       "read": [""], "write": [""]}'
```

`read` and `write` are lists of namespace prefixes and `""` means all of them,
so that is read and write everywhere — what a full mirror needs. For a node
that only holds `feeds`, name it and the key cannot reach past it:

```bash
  -d '{"key": "lb-to-feeds", "admin": false,
       "read": ["feeds"], "write": ["feeds"]}'
```

**Then, on the load balancer**, add the peer:

```bash
curl -H 'Authorization: <lb admin key>' \
  -X POST https://lb.example:9999/_management/api/galaxy/peers \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://new-node.example:9999", "key": "lb-to-new-node"}'
```

Leave `namespaces` out for a full mirror; name them for a partial one. It must
agree with the node's own `[storage] namespaces`.

The answer is the whole peer list, so nothing else has to be fetched. The same
thing is a form on the **Galaxy** page.

This needs a `peers_file` in `[galaxy]`. Without one the galaxy is read-only
over the API, and the page says so rather than letting a save fail.

### The node does not have to be up

A mirror that is down must still be addable, or a galaxy could not be rebuilt
after whatever took it down. It is shown offline until it answers.

### Give the new node peers of its own

This is the part that is easy to miss, and it is measured rather than
theoretical.

A new node starts **empty**. From the moment it is added, writes fan out to it
— but reads are spread by hashing, so a share of reads goes to a node that does
not have the history yet. With twenty values on an existing node and an empty
node added beside it:

```text
reads through the load balancer after adding the empty node: 13/20 now MISS
```

Thirteen values that are in the galaxy, reported absent. And it does not heal:
the node has no way to know what it is missing.

The fix is to give the new node a `[galaxy]` section naming at least one
existing node, and a non-zero `sync_interval`:

```toml
[galaxy]
sync_interval = 300
peers = [
  { url = "https://node-a.example:9999", key = "new-node-to-node-a" },
]
```

It then asks that node what it holds, compares, and pulls what it is missing.
While it does, it reports `catching_up` and the load balancer sends reads
elsewhere. With that in place, the same test:

```text
right after it starts    node-d: holds=['feeds/ips']  misses=0/20
```

The key for *that* direction is read-only — pulling is a read, and a node
catching up has no business writing on the node it pulls from:

```bash
  -d '{"key": "new-node-to-node-a", "admin": false,
       "read": [""], "write": []}'
```

A node with no `[galaxy]` at all never reports catching up, because it has
nothing to catch up from. That is a valid configuration — a node that only ever
holds what arrives from now on — as long as it is the one you meant.

## Changing one

Rotating a key, or changing what a node holds, is `PUT`:

```bash
curl -H 'Authorization: <lb admin key>' \
  -X PUT https://lb.example:9999/_management/api/galaxy/peers \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://new-node.example:9999", "key": "a-rotated-key"}'
```

Adding and changing are separate verbs on purpose. An upsert would mean that
typing an address that already exists silently replaces its key, and that key
is the one thing bounding what the load balancer may do there. `POST` on an
address already present answers `409`; `PUT` on one that is absent answers
`404`.

**The key is required even when only `namespaces` changes**, because it is
never read back: a peer key is a credential this server holds, and a topology
view is not a reason to hand it out.

## Taking one out of service

```bash
curl -H 'Authorization: <lb admin key>' \
  -X POST https://lb.example:9999/_management/api/galaxy/peers/enabled \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://node-b.example:9999", "enabled": false}'
```

The peer is **kept** — address, key, what it holds — and this server sends it
nothing at all: no forwarded request, no catch-up, no gossip, not even a health
probe. For a node going down for maintenance, or one you want to stop sending
data to without having to find its key again to put it back. `Disable` and
`Enable` on the Galaxy page are the same call.

It survives a restart, because it is written to the `peers_file`:

```toml
[[peers]]
url = "https://node-b.example:9999"
key = "lb-full"
enabled = false
```

**A namespace only that peer held is out of reach while it is off**, and reads
of it answer `421`. That is what taking a node out of service means rather than
a side effect of it — check the `Holds` column before you disable something.

Rotating a key leaves a peer disabled if it was. Two different decisions.

## Removing one

```bash
curl -H 'Authorization: <lb admin key>' -X DELETE \
  'https://lb.example:9999/_management/api/galaxy/peers?url=https%3A%2F%2Fnode-b.example%3A9999'
```

Nothing stored on the node is deleted; this server stops using it. Its health
is forgotten with it, so re-adding the same address starts unprobed rather than
inheriting a stale "offline".

## What you cannot change over the API

A peer written into `[galaxy] peers` in the configuration file:

```json
{"message":"https://node-a.example:9999 is declared in the configuration file,
 so removing it here would not last: it would come back at the next restart.
 Remove it from [galaxy] peers instead."}
```

That file is yours and the program does not rewrite it, so a change made here
would be undone by the next restart. Either edit it, or move the peer out of it
so the API owns it. `sightingdb --setup` writes a live `[galaxy]` section with
a `peers_file` and no peers in it, which is a valid galaxy and the easier
starting point.

## Watching it

```bash
curl -H 'Authorization: changeme' \
  https://lb.example:9999/_management/api/galaxy/peers
```

```json
{"peers":[
  {"url":"https://node-a:9999","namespaces":null,"fixed":false,"enabled":true,
   "health":{"online":true,"probed":true,"last_seen":1791678296,
             "latency_ms":1,"version":"0.7.1","error":null,
             "failures":0,"catching_up":false}}],
 "editable":true}

```

`probed: false` with `online: false` means "not asked yet", which is not the
same as down. `last_seen` is when this server last got a health reply from that
peer — nothing to do with a value's own `last_seen`, which is why the interface
calls the column **Last answered**.

![The galaxy, and the peers under it.](images/ui-galaxy.png){width=100%}

The graph colours a full mirror, a partial mirror and a router differently, and
red for a server that is not answering. `GET /_management/api/galaxy` walks the
peers, so one request describes a whole cascade.

## Keys across a galaxy

Each server has its own ACL, and the **Keys** page shows the ACL of the server
you are connected to and nothing else. The keys a *node* accepts live on that
node.

Two optional mechanisms connect them:

- **`gossip_interval`** pushes this server's keys to its peers, so a peer that
  was down for a key change picks it up. The push goes through the peer's own
  management interface, so the peer's ACL decides — this server can only
  administer a peer it holds an `admin` key for. The offer is *additive*: a
  revocation made while a peer was down does not reach it this way.

- **`acl_authority`** and **`acl_replaceable`** are the answer to that. Set
  `acl_authority` on the server that owns the galaxy's keys and
  `acl_replaceable` on each server that accepts them, and the owner's offer
  becomes the whole list, to be held exactly — which *does* remove. Both ends
  must agree, so a server with `acl_replaceable` off keeps its own keys and
  nothing is lost by not opting in. Setting both on one server is refused at
  startup: they would take turns overwriting each other.

`GET /_management/api/keys/drift` shows where a server's keys and its peers'
disagree. It needs `admin` on the peer key, which a deliberately narrow peer
key does not have — in which case it says so, which is a correct answer rather
than a failure.

## A checklist

Before a node joins:

- It has its **own `node_id`**. Nothing else in this chapter works if two
  servers share one.
- Its `[storage] namespaces` matches what the load balancer declares for it.
- It has a key for the load balancer, scoped to what that load balancer should
  reach.
- It has `[galaxy] peers` and a `sync_interval` of its own, so it backfills.
- The load balancer has a `peers_file`, so the addition survives a restart.
