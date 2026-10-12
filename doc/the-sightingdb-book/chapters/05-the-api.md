# The API

Every route takes the key in an `Authorization` header. There is no scheme
prefix — the key is the whole value.

```bash
curl -H 'Authorization: changeme' ...
```

`doc/routes.md` in the repository is the exhaustive version of this chapter,
with every status code. This is the part you will use.

## Writing

### One sighting

```bash
curl -H 'Authorization: changeme' \
  'http://localhost:9999/w/feeds/misp/ips?val=198.51.100.23'
```

```json
{"message":"ok","count":4,"new":false}
```

The namespace is the path. Everything after `/w/` up to the query string is
it, so it can be as deep as you like.

Optional parameters:

| Parameter | Effect |
| --- | --- |
| `timestamp=` | Record it as seen then, in Unix seconds, rather than now. |
| `ttl=` | Seconds until it stops being visible. |
| `tags=` | Tags to **merge** into whatever it already carries. |

```bash
curl -H 'Authorization: changeme' \
  'http://localhost:9999/w/feeds/misp/ips?val=198.51.100.23&tags=tlp:green,stix-type:ipv4-addr'
```

Writes merge tags rather than replacing them, so two feeds that each know
something different about a value both contribute. Taking a tag *off* is the
management interface's job — chapter 6.

### Many at once

`POST /wb` is the ingest path, and the one to use for anything over a handful.

```bash
curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
  -X POST http://localhost:9999/wb -d '{"items":[
    {"namespace":"feeds/misp/ips","value":"198.51.100.23","tags":"tlp:green"},
    {"namespace":"feeds/misp/ips","value":"203.0.113.7","timestamp":1791668207},
    {"namespace":"feeds/misp/domains","value":"login.phish.example","ttl":86400}
  ]}'
```

Every item is answered separately:

```json
{"message":"ok","written":3,"items":[
  {"index":0,"namespace":"feeds/misp/ips","value":"198.51.100.23",
   "status":"ok","count":5,"new":false},
  ...]}
```

`message` is `ok`, `partial` or `failed`. A batch where some items were refused
and others written is `partial` with HTTP 200 — **the ones that worked are
stored**, which is the point of per-item results. A batch that wrote nothing
because every item was refused by the ACL is `403`; one that wrote nothing for
mixed reasons is `400`.

### Checking a batch first

`POST /vwb` takes the same body and writes nothing:

```bash
curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
  -X POST http://localhost:9999/vwb -d '{"items":[...]}'
```

It answers with the same per-item shape, saying which items *would* be
accepted. It deliberately does not read the database, which is what lets it
promise that a passing item would be written rather than that it looks
plausible.

## Reading

### One value

```bash
curl -H 'Authorization: changeme' \
  'http://localhost:9999/r/feeds/misp/ips?val=198.51.100.23&noshadow'
```

```json
{"value":"198.51.100.23","first_seen":1791668207,"last_seen":1791668230,
 "count":5,"tags":"tlp:green","ttl":0,"consensus":1}
```

**`noshadow` matters.** Without it the read is recorded as a search, in a
`_shadow/` namespace beside the one you read. That is a feature — it answers
"which indicators do my analysts keep looking up?" — and a nuisance when you
are reading your own data in a loop.

```bash
curl -H 'Authorization: changeme' \
  'http://localhost:9999/r/_shadow/feeds/misp/ips?val=198.51.100.23&noshadow'
```

### With statistics

`/rs` is `/r` plus the hourly breakdown:

```json
{"value":"198.51.100.23", ..., "stats":{"1791666000":3,"1791669600":2}}
```

The keys are the Unix timestamp of the hour.

### A whole namespace

```bash
curl -H 'Authorization: changeme' 'http://localhost:9999/r/feeds/misp/ips'
```

### Just the size of one

```bash
curl -H 'Authorization: changeme' 'http://localhost:9999/r/feeds/misp/ips?count'
```

```json
{"namespace":"feeds/misp/ips","values":1284}
```

Maintained as values are written and deleted, so it is a lookup rather than a
walk — ask it as often as you like.

### Many values at once

```bash
curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
  -X POST http://localhost:9999/rb -d '{"items":[
    {"namespace":"feeds/misp/ips","value":"198.51.100.23","noshadow":true},
    {"namespace":"feeds/misp/ips","value":"203.0.113.99","noshadow":true}
  ]}'
```

```json
{"items":[
  {"value":"198.51.100.23","first_seen":1791668207,"last_seen":1791668230,
   "count":5,"tags":"tlp:green","ttl":0,"consensus":1},
  {"error":"Value not found","namespace":"feeds/misp/ips","value":"203.0.113.99"}]}
```

Results are positional: item *n* answers item *n*, and a miss is an error
object in place of an attribute rather than a gap. `/rbs` is the same with
statistics.

### What was written lately

```bash
curl -H 'Authorization: changeme' 'http://localhost:9999/_api/latest?limit=10'
```

```json
{"capacity":10000,"limit":10,"items":[
  {"namespace":"misp/domains","value":"bad.example","written":1791838382},
  {"namespace":"proxy/blocked","value":"evil.example","written":1791838382},
  {"namespace":"misp/ips","value":"203.0.113.7","written":1791838382}]}
```

The most recent writes, newest first, each with the namespace it went to — and
only those in namespaces **your key may read**. A key granted `r:misp` asking
the same question gets the two `misp` entries and never learns that `proxy`
was written to. The record is shared; the answer is per key.

- `limit` — how many, 100 by default. Anything over 1000 is capped to 1000
  rather than refused.
- `since` — only writes at or after this Unix time. Poll with the newest
  `written` you have seen, and skip what you already handled in that second.
- `namespace` — only that namespace and those below it.

A value written again moves to the front instead of being listed twice, so one
noisy feed does not push everything else out. `written` is when the write
*arrived*, which is what "latest" means; the sighting's own timestamp may have
been set in the past by the client.

The server remembers `latest_writes` entries in all (chapter 4), and that is
shared between every key. A key that can read only a quiet namespace may be
shown fewer than it asked for, because its values have been pushed out by
everyone else's. Raise `latest_writes` if that matters.

It is not an internal namespace, and could not be one: access is granted by
namespace path, so a key allowed to read `_latest` would see every write in
it. What is filtered is the namespace each value went to.

## Deleting

```bash
curl -H 'Authorization: changeme' 'http://localhost:9999/d/feeds/misp/ips'
```

Deletes the **whole namespace**. There is no delete-one-value route: a sighting
is a count over a window, and removing one observation from it is not a
coherent operation. Expire values with a `ttl` instead.

## What the status codes mean

| Code | Meaning |
| --- | --- |
| `200` | Done. For a batch, possibly `partial` — read `items`. |
| `400` | The request is malformed, or a batch failed for mixed reasons. |
| `401` | No key. |
| `403` | The key may not do this, or you wrote to an internal namespace. |
| `404` | No such namespace, or no such value in it. |
| `421` | **Nowhere in reach stores that namespace.** See chapter 8. |
| `500` | Something broke; the message says what. |
| `502` | A mirror that holds this could not be reached. |
| `508` | A forwarded request ran out of hops; your galaxy has a cycle. |

`421` and `502` only appear in a galaxy, and the distinction between them and
`404` is deliberate: "no such namespace", "nowhere in reach stores it" and "the
server that has it is down" are three different answers, and only one of them
is worth retrying.

## Namespaces beginning with `_`

Internal. `_all` is the consensus tally, `_shadow/*` is what has been searched
for, `_config` is server state.

They are **readable** — `/r/_all?val=x` is how you ask how many namespaces have
seen a value — and **not writable from outside**, by anything, at any
permission level. A client that could write `_all` could forge consensus: one
honest write plus five forged ones, and a value looks corroborated by six
independent feeds. `_config` is not readable either.

## The route list

```bash
curl http://localhost:9999/
```

Needs no key and lists every route with a line each. `GET /i` reports the
version, and `GET /_api/openapi.yaml` is the whole API as an OpenAPI 3
document, which a test keeps honest.
