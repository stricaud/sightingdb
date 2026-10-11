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

Every id is a UUIDv5 over a fixed namespace UUID and what the object describes.
Two consequences, both useful:

- Exporting the same data twice produces a **byte-identical** bundle, so an
  export can be diffed, cached, or published on a schedule without looking like
  it changed.
- One value in two namespaces yields **one indicator with two sightings**,
  because the indicator's id depends on the value and the sightings' on the
  namespace.

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
