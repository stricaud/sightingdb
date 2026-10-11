Adding a new node to a galaxy
=============================

Simply with a POST request: a load balancer takes a new node from

	POST /_management/api/galaxy/peers

and starts using it at once — no restart, which matters because restarting a
load balancer is a gap in service for everything behind it. The same thing is
on the **Galaxy** page of the management interface, which is the easier way to
do it once and the API is the way to do it fifty times.

There is one thing to get right that the POST cannot do for you, and it is in
[Give the new node peers of its own](#give-the-new-node-peers-of-its-own).
Skipping it makes reads miss data that is there.


Before you start
----------------

**The load balancer needs a `peers_file`.** Peers added through the API are
written to it, which is what makes them survive a restart:

	[galaxy]
	peers_file = "/var/lib/sightingdb/peers.toml"

A file of its own because `sightingdb.toml` is yours — it is comment-rich and
hand-maintained, and a program that rewrote it would destroy those comments.
Without a `peers_file` the galaxy is read-only over the API and the interface
says so rather than letting a save fail. `sightingdb --setup` writes one for
any mode that forwards.

**The new node needs a key for the load balancer to use.** Create it on the
*node*, because it is the node's own ACL that decides what the key opens. Make
it the narrowest thing that does the job:

	# on the new node
	$ curl -H 'Authorization: <node admin key>' \
	    -X POST https://new-node.example:9999/_management/api/keys \
	    -H 'Content-Type: application/json' \
	    -d '{"key": "lb-to-new-node", "admin": false,
	         "read": [""], "write": [""]}'

`read` and `write` are lists of namespace prefixes, and `""` means all of them.
So that is read and write everywhere, which is what a full mirror needs. For a
node that only holds `feeds`, name it instead and the key cannot reach past it:

	    -d '{"key": "lb-to-feeds-node", "admin": false,
	         "read": ["feeds"], "write": ["feeds"]}'

This is the bound on what the load balancer may do there: a compromised load
balancer cannot write outside what the node's ACL allows, however it is
configured, and that is not something it can talk its way out of. Never give a
peer key `admin` — nothing in forwarding needs it.

**The new node needs its own `node_id`.** Sightings are counted per node, and
two nodes sharing a name would each take the other's contributions for its own
— the merge meant to reconcile them would discard one side instead.

	[daemon]
	node_id = "new-node"


Adding it
---------

	$ curl -H 'Authorization: <lb admin key>' \
	    -X POST https://lb.example:9999/_management/api/galaxy/peers \
	    -H 'Content-Type: application/json' \
	    -d '{"url": "https://new-node.example:9999",
	         "key": "lb-to-new-node"}'

The answer is the whole peer list, so nothing else has to be fetched:

	{"peers":[
	  {"url":"https://node-a.example:9999","namespaces":null,"fixed":true,
	   "health":{"online":true,"probed":true,"last_seen":1791670776,
	             "latency_ms":1,"version":"0.6.1","error":null,
	             "failures":0,"catching_up":false}},
	  {"url":"https://new-node.example:9999","namespaces":null,"fixed":false,
	   "health":{"online":false,"probed":false,"last_seen":0,
	             "failures":0,"catching_up":false}}],
	 "editable":true}

`probed: false` with `online: false` means "not asked yet", which is not the
same as down — the health poller reaches it within `health_interval`.

**A partial mirror** says what it holds. Leave `namespaces` out for a full
mirror; that is the common case and the one a reader should assume:

	-d '{"url": "https://new-node.example:9999",
	     "key": "lb-to-new-node",
	     "namespaces": ["feeds", "myorg/ips"]}'

This has to agree with the node's own `[storage] namespaces`. It is declared
here rather than asked of the node because asking would need the peer key to
carry an `admin` grant, and the point of that key is to be the narrowest thing
that works.

**The node does not have to be reachable.** A mirror that is down must still be
addable, or a galaxy could not be rebuilt after whatever took it down. It is
shown offline until it answers.

**Its own address is refused**, since a server mirroring itself is never what
was meant. Two load balancers pointing at each other is *not* refused: that is
cascading, and `max_hops` is what makes it safe.


Give the new node peers of its own
----------------------------------

A new node starts empty. From the moment it is added, writes fan out to it —
but reads are spread across the mirrors by hashing the value, so a share of
reads will be sent to a node that does not have the history yet.

This is measured, not theoretical. With 20 values on an existing node and an
empty node added beside it:

	reads through the load balancer after adding the empty node: 13/20 now MISS

Thirteen values that are in the galaxy, reported as absent. And it does not
heal: the node has no way to know what it is missing.

The fix is to give the new node a `[galaxy]` section naming at least one
existing node, and a non-zero `sync_interval`:

	[galaxy]
	sync_interval = 300
	peers = [
	  { url = "https://node-a.example:9999", key = "new-node-to-node-a" },
	]

It then asks that node what it holds, compares, and pulls what it is missing —
and it only ever pulls namespaces it stores itself, so a partial mirror stays
partial. While it is doing that it reports `catching_up`, and **the load
balancer sends reads elsewhere until it is done**, which is what makes the
backfill invisible rather than a window of wrong answers. Writes keep going to
it throughout: they land directly, and the catch-up fills in the history behind
them.

With that in place, the same test:

	right after it starts    node-d: holds=['feeds/ips']  misses=0/20

The key for that direction is a **read-only** key, because pulling is a read
and a node catching up has no business writing on the node it pulls from:

	# on node-a, for the new node to use
	    -d '{"key": "new-node-to-node-a", "admin": false,
	         "read": [""], "write": []}'

A node with no `[galaxy]` at all never reports `catching_up`, because it has
nothing to catch up from; that is why the empty node above was sent reads
immediately. If you genuinely want a node that only ever holds what arrives
from now on, that is the configuration for it — just know that is what you are
choosing.


Checking it worked
------------------

	$ curl -H 'Authorization: <lb admin key>' \
	    https://lb.example:9999/_management/api/galaxy/peers

Look for `online: true` and a `version` that matches the rest of the galaxy. A
galaxy running mixed versions is worth seeing before it misbehaves.

Then write something and read it back through the load balancer:

	$ curl -H 'Authorization: <client key>' \
	    'https://lb.example:9999/w/feeds/ips?val=203.0.113.99'
	$ curl -H 'Authorization: <client key>' \
	    'https://new-node.example:9999/r/feeds/ips?val=203.0.113.99&noshadow'

Asking the new node *directly* is the point: it proves the write reached it
rather than being served from somewhere else.

`GET /_management/api/galaxy` draws the whole cascade, and the interface
renders it under **Galaxy** — routers as diamonds, full and partial mirrors in
different colours, red for a server that is not answering.


Changing and removing
---------------------

Changing is `PUT`, not `POST`:

	$ curl -H 'Authorization: <lb admin key>' \
	    -X PUT https://lb.example:9999/_management/api/galaxy/peers \
	    -H 'Content-Type: application/json' \
	    -d '{"url": "https://new-node.example:9999",
	         "key": "a-rotated-key",
	         "namespaces": ["feeds"]}'

They are separate verbs on purpose. An upsert would mean that typing an address
that already exists silently replaces its key, and that key is the one thing
bounding what the load balancer may do there. `POST` on an address already
present answers `409`; `PUT` on one that is absent answers `404`.

The key is required even when only `namespaces` changes, because it is never
read back: a peer key is a credential the load balancer holds, and a topology
view is not a reason to hand it out.

Taking one out of service without removing it:

	$ curl -H 'Authorization: <lb admin key>' \
	    -X POST https://lb.example:9999/_management/api/galaxy/peers/enabled \
	    -H 'Content-Type: application/json' \
	    -d '{"url": "https://new-node.example:9999", "enabled": false}'

The peer is kept — address, key, namespaces — and this server sends it nothing
at all: no forwarded request, no catch-up, no gossip, not even a health probe.
Use it when a node is going down for maintenance, or when you want to stop
sending it data without having to find its key again to put it back. `Disable`
and `Enable` in the Galaxy page are the same call.

It is a separate call from `PUT` on purpose: `PUT` needs the key, and the key
is never read back, so a toggle would mean retyping a credential to change
something unrelated to it. For the same reason, rotating a peer's key leaves it
disabled if it was — those are two different decisions.

**A namespace only that peer held is out of reach while it is off**, and reads
of it answer `421`. That is what taking a node out of service means, so check
first that something else holds what it holds — the `Holds` column is there for
this.

Removing:

	$ curl -H 'Authorization: <lb admin key>' -X DELETE \
	    'https://lb.example:9999/_management/api/galaxy/peers?url=https%3A%2F%2Fnew-node.example%3A9999'

By query rather than a path segment because the value is a URL, which a path
would have to encode and middleware is free to normalise. Nothing stored on the
node is deleted; the load balancer stops using it. Its health is forgotten with
it, so re-adding the same address starts unprobed rather than inheriting a
stale "offline".

**Removing a node removes a copy, not the data.** If it was the only node
holding a namespace, that namespace is no longer reachable through this load
balancer — reads answer `421 Misdirected Request`, which says "nowhere in reach
stores this" rather than pretending it never existed.


What you cannot do this way
---------------------------

A peer written into `[galaxy] peers` in the configuration file shows up with
`fixed: true` and cannot be changed or removed over the API:

	{"message":"https://node-a.example:9999 is declared in the configuration
	 file, so removing it here would not last: it would come back at the next
	 restart. Remove it from [galaxy] peers instead."}

That is deliberate. The configuration is yours and this program does not
rewrite it, so a change made here would be undone by the next restart —
refusing is better than appearing to work. Either edit that file, or move the
peer out of it so the API owns it.


Adding a load balancer rather than a node
-----------------------------------------

The same POST. A peer is a peer: if what you add is itself a load balancer, you
have a cascade, and a request passed to it goes on to its own nodes.

Two things to know. `max_hops` is spent on every hop and refused at zero, which
is what stops a miswired cycle — a cycle would otherwise inflate every count
travelling round it. And a cascade preserves the entry point a client talked to,
so a write forwarded twice is still counted once, for the server the client
actually reached.


When it does not work
---------------------

| What you see | What it means |
| --- | --- |
| `409 ... is already in this galaxy` | Use `PUT` to change it. |
| `409 ... declared in the configuration file` | It is in `[galaxy] peers`; edit that, or move it out. |
| `409 No peers_file is configured` | Add `peers_file` to `[galaxy]` and restart. |
| `409 ... no [galaxy] section` | The server was not set up to forward at all. Add one with a `peers_file` and restart. |
| `400 ... is this server's own address` | You are adding the load balancer to itself. |
| `400 ... needs an http:// or https:// url` | Give a scheme. |
| `400 ... has no key` | The key is what bounds what this server may do there; there is no default. |
| Added, but `online: false` with `probed: true` | The address is wrong, the node is down, or TLS is being rejected — the `error` field says which. For a galaxy of self-signed instances set `verify_tls = false`. |
| Added and online, but reads of it `404` | It is empty and has no peers to catch up from. See [Give the new node peers of its own](#give-the-new-node-peers-of-its-own). |
| Shown as `disabled`, and nothing reaches it | Somebody turned it off. `Enable` puts it back; nothing was lost. |
| `421` on a namespace that exists | Every peer holding it is disabled or removed. Nowhere in reach stores it. |
| Writes to it refused in a bulk response | The key you gave the load balancer is narrower than the namespaces being written, or the node's `[storage]` does not hold them. The per-item error says which. |

A galaxy to try all of this against, in four containers:
[doc/docker/](docker/).
