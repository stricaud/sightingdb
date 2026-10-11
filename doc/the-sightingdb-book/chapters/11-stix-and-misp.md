# STIX and MISP

Chapter 1 made the claim that SightingDB stores exactly what a STIX sighting
is. This is the chapter where that pays.

## Exporting STIX 2.1

```bash
curl -H 'Authorization: changeme' \
  'http://localhost:9999/stix/feeds/misp/ips' > bundle.json
```

A namespace becomes a bundle shaped after the OASIS *Sighting of an Indicator*
example: for each value an `indicator` carrying the pattern, and a `sighting`
that refers to it with the count and the window.

```json
{"type":"bundle","id":"bundle--...","objects":[
  {"type":"identity","id":"identity--...","name":"SightingDB", ...},
  {"type":"indicator","id":"indicator--...",
   "pattern":"[ipv4-addr:value = '198.51.100.23']","pattern_type":"stix",
   "object_marking_refs":["marking-definition--..."], ...},
  {"type":"sighting","id":"sighting--...",
   "count":5,"first_seen":"...","last_seen":"...",
   "sighting_of_ref":"indicator--...",
   "where_sighted_refs":["identity--..."],
   "x_sightingdb_namespace":"feeds/misp/ips"},
  {"type":"marking-definition","name":"TLP:AMBER", ...}]}
```

The namespace travels as `x_sightingdb_namespace`, which is a custom property
and so carries the `x_` prefix the specification requires.

### Ids are derived, not minted

**Minting** an id is creating a fresh one. A STIX identifier is the object's
type, two dashes, and a UUID:

```text
indicator--9299f726-ce06-492e-8472-2b52ccb53191
```

Normally that UUID is a **version 4** — random. Minting one takes nothing but
a source of randomness, which is why it is the default: no agreement is
needed, and two parties will never collide. The cost is that it is new every
time. Export the same value twice and you get two unrelated ids, and nothing
downstream can tell they describe the same thing.

A **version 5** UUID is the other kind. It is a hash of two inputs:

- a **namespace UUID**, chosen once and kept forever, and
- a **name** — any string, as long as you can produce the same one again.

Same two inputs, same UUID, on any machine, in any language, for ever. So
"what it takes to mint" is really the question of which of those two you are
doing: with v4, a random number; with v5, a namespace you have fixed and a
name you can reconstruct.

SightingDB uses v5 everywhere, with a namespace of its own:

```text
3ef11775-6174-4718-92bf-16705b732650
```

and these names:

| Object | The name that is hashed |
| --- | --- |
| indicator | `indicator:<observable type>:<value>` |
| sighting | `sighting:<namespace>:<observable type>:<value>` |
| identity | `identity:<name>` |
| bundle | `bundle:<namespaces, comma separated>` |

Which means you can mint the same ids yourself, without this server:

```python
import uuid

SIGHTINGDB = uuid.UUID("3ef11775-6174-4718-92bf-16705b732650")

value, observable, namespace = "evil.example", "domain-name", "feeds/misp/domains"

print("indicator--" + str(uuid.uuid5(SIGHTINGDB, f"indicator:{observable}:{value}")))
print("sighting--"  + str(uuid.uuid5(SIGHTINGDB, f"sighting:{namespace}:{observable}:{value}")))
```

Those are exactly the ids the export produces for that value in that
namespace — not an illustration of the idea, the same two strings hashed the
same way. And they will not change between releases: the namespace above is a
constant precisely so that they cannot.

Note which name carries what. The indicator's has only the observable type and
the value in it, so the same domain seen in four namespaces is one indicator.
The sighting's has the namespace as well, so each of those four is its own
sighting of it.

> The specification asks for v4 on objects like indicators and sightings, and
> *requires* v5 for cyber-observable objects, with a namespace it fixes
> itself. Using v5 everywhere is therefore a deliberate departure: it trades
> the guarantee that two publishers never collide for the guarantee that the
> same data always produces the same bundle. For a database whose job is to be
> re-exported on a schedule, that is the better trade — and the namespace
> being ours is what keeps the collision risk where v4 would have put it.

Two consequences, both useful:

- Exporting the same data twice produces a **byte-identical** bundle, so an
  export can be diffed, cached, or published on a schedule without looking like
  it changed.
- One value in two namespaces yields **one indicator with two sightings**,
  because the indicator's name has only the value in it and the sighting's has
  the namespace too.

A value that arrived *as* STIX is the exception: the importer records the id
its publisher gave it as a `stix-id:` tag, and the export uses that rather than
deriving one. A bundle that goes out of here and comes back refers to the same
objects it did before.

### What decides the pattern

An indicator is a pattern, and there is no pattern without a type. The type is
resolved in this order:

1. A `stix-type:` tag on the value.
2. The `[stix.types]` mapping for the namespace, read backwards.
3. The shape of the value itself.

A value that none of those identify is **skipped** and counted in
`X-SightingDB-Skipped`, never guessed at. If you would rather have it, ask:

```bash
curl -H 'Authorization: changeme' \
  'http://localhost:9999/stix/feeds/misp/ips?untyped=include'
```

Those go out as a custom observable type, flagged, so a consumer can tell them
from a value whose type is actually known.

### Headers say what you got

| Header | Meaning |
| --- | --- |
| `X-SightingDB-Exported` | Values in the bundle. |
| `X-SightingDB-Skipped` | Values left out for having no observable type. |
| `X-SightingDB-Untyped` | Of those exported, how many went out untyped. |
| `X-SightingDB-Namespaces` | How many namespaces contributed. |
| `X-SightingDB-Truncated` | The namespace holds more than `limit` allowed. |
| `X-SightingDB-Missing` | Namespaces asked for that do not exist. |

A bundle that quietly dropped a third of a namespace would be worse than one
that refused, so it says.

### A subtree, or several namespaces

```bash
curl -H 'Authorization: changeme' \
  'http://localhost:9999/stix/feeds?recursive'
```

```bash
curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
  -X POST http://localhost:9999/_api/stix \
  -d '{"namespaces":["feeds/misp/ips","watchlist/ips"],"q":"198.51","limit":500}'
```

Through a load balancer, each namespace is exported by the mirror that holds it
and the bundles are folded into one. The result is byte-identical to what a
single server holding all of them would produce — the derived ids make the
merge a deduplication rather than a reconciliation.

### Configuring who you are

```toml
[stix]
identity = "Beta Cyber Intelligence Company"
identity_class = "organization"

[stix.types]
"feeds/misp/ips" = "ipv4-addr"
"feeds/misp/domains" = "domain-name"
"feeds/misp/hashes" = "file.SHA-256"
```

`identity` is who the bundle is published by and who the sightings are
attributed to when no `identity:` tag says otherwise. `[stix.types]` saves
tagging every value in a namespace that only ever holds one kind of thing.

> Verify changes against the OASIS library rather than by eye:
> `pip install stix2`, then
> `stix2.parse(raw, allow_custom=True, version="2.1")`. `allow_custom` is
> needed only for `x_sightingdb_namespace`.

## Importing STIX

```bash
sightingdb --import-stix ./bundles/
```

A file or a directory. It loads, writes, saves and exits — no listeners start,
so it is safe to run against a server's data directory while that server is
stopped.

A STIX sighting's `count` is honoured, and its `first_seen`/`last_seen` become
the window: the first write lands at `first_seen` and the rest at `last_seen`,
so both ends survive. Tags are written from what the bundle says — the
observable type, the markings, who published it — which is what makes an
import and then an export round-trip.

## Importing from MISP

MISP publishes over ZMQ, and SightingDB subscribes:

```toml
[zmq]
url = "tcp://misp.example:50000"
format = "misp"
default_namespace = "misp/other"
require_to_ids = false

[zmq.types]
ip-src = "misp/ips"
ip-dst = "misp/ips"
domain = "misp/domains"
hostname = "misp/domains"
url = "misp/urls"
md5 = "misp/hashes"
sha256 = "misp/hashes"
```

Attributes are read from single-attribute publications and from whole events,
including attributes nested inside objects — which is where most of a modern
MISP event's attributes live. Only mapped types are ingested unless
`default_namespace` is set, and `require_to_ids = true` limits ingest to
attributes MISP flagged as actionable.

MISP's timestamps are preserved, so a replayed event does not claim to have
been seen today.

### What becomes a tag

| Tag | From |
| --- | --- |
| `misp-type:` | The attribute type, as published. |
| `stix-type:` | Translated from it, where there is a one-to-one mapping. |
| `misp-category:` | The attribute's category. |
| `misp-event:` | The event it came from. |
| `description:` | The attribute's comment, if it has one. |
| *everything else* | MISP's own tags, carried across as published. |

MISP's tags are already `namespace:predicate` shaped — `tlp:amber`,
`misp-galaxy:threat-actor="Callisto"` — so they come across unchanged, which is
what makes `tlp:` work end to end.

**Tags on the event are inherited by its attributes.** MISP keeps the TLP
marking on the event, and reading attribute tags alone would lose it: a
sighting from a `tlp:amber` event would arrive unmarked and export unmarked,
which is the one kind of loss here that could mislead someone about how a value
may be shared.

Where the two contradict each other the attribute wins and the event's is
dropped rather than added beside it — a value tagged both `tlp:amber` and
`tlp:white` says nothing useful. That applies only to taxonomies where one
value can be true at a time, which today means `tlp:`; most are genuinely
multi-valued, so an event and an attribute can each contribute a
`misp-galaxy:` tag and both are kept.

## A feed to try it with

CIRCL publish a public MISP OSINT feed at
<https://www.circl.lu/doc/misp/feed-osint/>. The galaxy sample in `doc/docker`
is loaded from one of its events, converted by `doc/docker/fetch-demo-data.py`
into the shape this ingest produces — same namespaces, same tags. It is a
useful thing to read if you are writing an importer of your own.

Two cautions if you take data from it yourself. The feed is **not uniformly
public**: most events are `tlp:white` or `tlp:clear`, but some are `tlp:green`
and a few carry no marking at all, and `tlp:green` means the community rather
than the world. And it states **no licence** — TLP is a handling designation,
not a copyright grant. The script that converts it refuses anything not marked
for unrestricted sharing for exactly that reason.
