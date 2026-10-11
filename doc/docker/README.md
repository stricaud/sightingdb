A SightingDB galaxy in four containers
======================================

One load balancer and three nodes, with real demo data in it. From the
repository root:

	$ docker compose -f doc/docker/docker-compose.yml up --build

Then open <http://localhost:9999/_management> and sign in with `demo`.

	                       clients
	                          │
	                          ▼
	                 ┌─────────────────┐
	                 │       lb        │  stores nothing; forwards everything
	                 │  localhost:9999 │
	                 └────────┬────────┘
	           ┌──────────────┼──────────────┐
	           ▼              ▼              ▼
	     ┌──────────┐   ┌──────────┐   ┌──────────────┐
	     │  node-a  │◄─►│  node-b  │   │    node-c    │
	     │   full   │   │   full   │   │   misp/ips   │
	     │  mirror  │   │  mirror  │   │     only     │
	     │   :9991  │   │   :9992  │   │    :9993     │
	     └──────────┘   └──────────┘   └──────────────┘
	           ▲                              │
	           └──────────────────────────────┘
	                    catches up from

The nodes are on 9991–9993 as well so you can see the difference between what
one node holds and what the galaxy holds. That is a convenience for reading
this, not a pattern: clients talk to the load balancer.

`docker compose -f doc/docker/docker-compose.yml down -v` throws it all away,
volumes included.


What each file is
-----------------

| | |
| --- | --- |
| `docker-compose.yml` | The four servers, the seed job, and a list of things to try at the bottom. |
| `lb.toml` | The load balancer: stores nothing of its own, and names no peers — `seed.sh` joins them through the API so they stay editable. |
| `node-a.toml`, `node-b.toml` | Full mirrors, each catching up from the other. |
| `node-c.toml` | A partial mirror: `misp/ips` and nothing else. |
| `seed.sh` | Joins the three nodes to the galaxy, then writes the demo data through the load balancer. Once. |
| `demo-data.json` | The indicators, with their provenance in `_source`. |
| `demo-data.env` | Two values `seed.sh` points at, so it names no indicator itself. |
| `fetch-demo-data.py` | Regenerates both from CIRCL's feed. |

Every config is mounted read-only, so editing one and restarting that container
is the whole loop:

	$ docker compose -f doc/docker/docker-compose.yml restart node-c


Where the data comes from
-------------------------

Real indicators from [CIRCL's public MISP OSINT
feed](https://www.circl.lu/doc/misp/feed-osint/) — one event, converted by
`fetch-demo-data.py` into the shape SightingDB's own MISP ingest produces: the
namespace from the attribute type, and tags `misp-type:`, `stix-type:`,
`misp-category:`, `misp-event:`, `description:` plus MISP's own tags carried
across as published. So it is shaped like data that really arrived from MISP
rather than like something invented for a screenshot.

**On the terms.** The event is published by CIRCL and marked `tlp:white` and
`tlp:clear` — "may be shared without restriction". That is a *handling*
designation rather than a copyright licence: the feed states no licence, and
CIRCL reserves copyright on its site. It is kept here as a small attributed
sample, with the source event, the publisher and the retrieval date recorded in
`demo-data.json`. If that is not a basis you want in your tree, delete the two
generated files and run `fetch-demo-data.py` yourself when you want the demo.

The generator **refuses** an event that is not marked for unrestricted sharing
— the feed also carries some `tlp:green` and a few untagged events, which are
almost certainly publication slips and are exactly what must not be committed
— and refuses one published by anyone other than CIRCL, so the provenance of
anything committed stays with one organisation. `--force` overrides both; do
not commit the result.

	$ python3 doc/docker/fetch-demo-data.py --list           # recent events
	$ python3 doc/docker/fetch-demo-data.py --uuid <uuid>    # pick another

These are someone else's published observations, and a dated snapshot of a feed
that is rewritten daily. Read as data, not as advice.


What the demo is for
--------------------

**Namespace routing.** `misp/ips` is on all three nodes; `misp/domains`,
`misp/urls`, `misp/hashes` are on the two full mirrors only. Ask node-c what it
actually stores:

	$ curl -H 'Authorization: demo' http://localhost:9993/_api/namespaces
	{"namespaces":["misp/ips"]}

Then ask it for a domain anyway. It answers — by **forwarding** to a node that
has it, which the response says:

	$ curl -si -H 'Authorization: demo' \
	    'http://localhost:9993/r/misp/domains?val=lapas.live&noshadow' \
	    | grep -i x-sightingdb-forwarded
	x-sightingdb-forwarded: 1

**Counting that mirroring does not inflate.** Three writes through the load
balancer are three sightings, not nine. The per-node breakdown shows why: every
copy is attributed to the entry point the client actually reached, so merging
two mirrors that already agree changes nothing.

	$ curl -H 'Authorization: demo' \
	    'http://localhost:9991/r/misp/ips?val=45.15.156.24&noshadow&for_merge'
	{"counts":{"lb":12}, ...}

**The capability bound.** node-c gives the load balancer `rw:misp/ips` and
nothing else. The load balancer cannot exceed that, because it is node-c that
decides:

	$ curl -H 'Authorization: lb-ips' -X POST http://localhost:9993/wb \
	    -H 'Content-Type: application/json' \
	    -d '{"items":[{"namespace":"misp/domains","value":"x"}]}'
	{"message":"failed","written":0,"items":[{...,"status":"error",
	 "error":"API key is not permitted to write this namespace."}]}

**Self-healing.** Stop a node, write through the load balancer, start it again,
and it pulls what it missed within `sync_interval` (30s here). While it is
catching up the load balancer sends reads elsewhere, so the backfill is
invisible rather than a window of wrong answers.

**Tags.** The feed's own MISP machine tags are all there. `tlp:` is coloured
from MISP's own taxonomy; the `misp-galaxy:`, `osint:` and `type:` families
arrive undefined and are listed as seen-but-not-defined, one click from being
adopted. A tag edited on one server is pushed to the mirrors as it is changed.

**STIX export, through the load balancer.** The bundle is byte-identical to the
one the node holding the data would produce, including for a subtree spanning
several mirrors:

	$ curl -H 'Authorization: demo' 'http://localhost:9999/stix/misp?recursive'


Which page shows what
---------------------

The two that are easy to confuse:

**Keys** shows the ACL of **the server you are connected to** — nothing else.
On the load balancer that is just `demo`, because the keys the *nodes* accept
live on the nodes. Open <http://localhost:9991/_management> and its Keys page
shows `lb-full` and `peer-full` with the namespaces each may read and write;
node-c's shows `lb-ips` scoped to `misp/ips`. There is no page that edits
another server's keys unless you give this one `admin` there, which the sample
deliberately does not — see below.

**Galaxy** is where a node is configured *as a peer*: its address, **the key
this load balancer authenticates to it with**, and **which namespaces it
holds**. That is the Peers table under the graph, and `Add a peer` / `Edit`
is the form for all three. The key is never displayed — it is a credential
this server holds, so editing one means typing a new one rather than seeing
the old.

`Last answered` in that table is when this load balancer last got a health
reply from that node. It is about the server, not about any value, and has
nothing to do with a value's own `last_seen`.

`Disable` keeps a node and sends it nothing — no requests, no catch-up, not
even a probe — which is how you take one out of service without losing the key
needed to put it back. Try it on node-c and then read `misp/ips`: the other two
hold it as well, so nothing changes. Try it on node-a *and* node-b and a read
of `misp/domains` answers `421`, because nowhere in reach stores it any more.

The nodes here are joined through the API by `seed.sh`, so all three are
editable. Had they been written into `[galaxy] peers` in `lb.toml` they would
show the same information but read-only, because that file is yours and the
program does not rewrite it.


Keys
----

`demo` gets you in everywhere. The rest exist to show that a peer key is a
capability:

| Key | Where | What it opens |
| --- | --- | --- |
| `demo` | everywhere | read, write and admin |
| `lb-full` | node-a, node-b | `rw` — a full mirror has to take any namespace |
| `lb-ips` | node-c | `rw:misp/ips` only. This is the interesting one |
| `peer-full` | node-a, node-b | `r` — catching up is a read |

The load balancer's keys live in a file the interface rewrites, so you can
create properly scoped ones under **Keys**. The nodes declare theirs inline in
their `.toml`, which is what lets `lb-ips` be narrower than full access — an
`acl_file` that does not exist yet starts empty and would discard them. The
cost is that a node's keys are read-only in its own interface here; edit the
file and `docker compose restart node-c`.

**No peer key has `admin`**, which is the point — a compromised load balancer
should not be able to administer the nodes. Two things follow, and both are
deliberate rather than broken: the galaxy graph cannot ask the nodes about
*their* peers, so it draws this server's own peers from its configuration and
labels them "as configured here"; and the key-drift panel under Keys has
nothing to compare, since comparing means reading another server's key list.
Giving a peer key `admin` enables both, and also the one-place key management
in the README's galaxy section — that is a decision about how much a load
balancer is trusted, not a default.

This is a demo on a private Docker network: no TLS, and the keys are in the
files you are reading. For anything real, terminate TLS in front of the
containers or mount a key and certificate, and do not use `demo`.


Adding a fourth node
--------------------

Without editing any of these files: [doc/ADDING-NEW-NODE.md](../ADDING-NEW-NODE.md).
The load balancer here has a `peers_file`, so the **Galaxy** page can add,
change and remove nodes, and they take effect without a restart.
