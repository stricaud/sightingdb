SightingDB routes
=================

Every HTTP route, with a real request and the response it actually returns.

The examples below were taken from a running 0.5.9 instance on
`http://127.0.0.1:9999` with `authenticate = true` and these keys:

	[acl]
	"changeme"   = "rw, admin"      # everything, including the management interface
	"analyst"    = "r:feeds"        # read feeds/* and nothing else
	"feedwriter" = "rw:feeds"       # read and write feeds/*

Timestamps and generated ids differ on your machine; everything else is
verbatim. A production instance serves TLS, so use `https://` and `-k` if the
certificate is self-signed.

Contents
--------

- [Conventions](#conventions)
- [Sightings](#sightings) — `/w` `/r` `/r?count` `/rs` `/d`
- [Bulk](#bulk) — `/wb` `/vwb` `/rb` `/rbs`
- [STIX export](#stix-export) — `/stix` `/_api/stix`, [subtrees](#exporting-a-whole-subtree), [untyped values](#values-with-no-observable-type)
- [Storage](#storage) — `/_api/tier`
- [Service](#service) — `/health` `/i` `/` `/_api/openapi.yaml` `/c`
- [Management interface](#management-interface) — `/_management/*`
- [Status codes](#status-codes)


Conventions
-----------

**Authentication.** Every data and management route takes the key in an
`Authorization` header, as the key itself with no scheme:

	Authorization: changeme

`/health`, `/i` and `/` need no key. When `authenticate = false` the data
routes do not either — the management interface always does.

**Namespaces are paths.** `feeds/misp/ips` is one namespace, not three, and it
appears in the URL as a path: `/r/feeds/misp/ips?val=1.2.3.4`. Storage is one
file per *top-level* namespace, which is the unit kept in memory or evicted.

**A value is not in the path.** It is always `?val=` or a JSON field, so a
value containing `/` needs no special handling.

**Shadow sightings.** A read records that something was looked for, under
`_shadow/<namespace>`, so you can see how often a value was searched for —
including values that were never there. Add `noshadow` to suppress it. Every
read example below uses it, to keep the examples from affecting each other.

**Consensus** is how many namespaces have seen a value, not how many times it
was written.


Sightings
---------

### `GET /w/<namespace>?val=<value>` — record a sighting

Counts one sighting, creating the namespace if it is new, and answers with the
running count.

| parameter | | |
| --- | --- | --- |
| `val` | required | the value being sighted |
| `timestamp` | optional | Unix seconds; absent means now |
| `ttl` | optional | seconds from the last sighting until the value expires; absent leaves what it had, 0 clears it |
| `tags` | optional | comma-separated, **merged** with whatever the value already carried |

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/w/feeds/misp/ips?val=1.2.3.4&tags=stix-type:ipv4-addr,tlp:amber'
	{"message":"ok","count":1}

Sighting it again returns the new count. The count comes back from inside the
lock that incremented it, so two concurrent writers get 1 and 2, never 1 and 1:

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/w/feeds/misp/ips?val=1.2.3.4'
	{"message":"ok","count":2}

With an explicit time and an expiry:

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/w/feeds/misp/domains?val=evil.example&timestamp=1566624658&ttl=86400'
	{"message":"ok","count":1}

Without `val`:

	$ curl -H 'Authorization: changeme' 'http://127.0.0.1:9999/w/feeds/misp/ips'
	{"message":"Did not receive a val= argument in the query string."}     # 400

### `GET /r/<namespace>?val=<value>` — read a value

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/r/feeds/misp/ips?val=1.2.3.4&noshadow'
	{"value":"1.2.3.4","first_seen":1790264378,"last_seen":1790264378,"count":2,
	 "tags":"stix-type:ipv4-addr,tlp:amber","ttl":0,"consensus":1}

`consensus` rises as other namespaces see the same value:

	$ curl -H 'Authorization: changeme' 'http://127.0.0.1:9999/w/feeds/other?val=5.5.5.5'
	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/r/feeds/manual?val=5.5.5.5&noshadow'
	{"value":"5.5.5.5","first_seen":1790264662,"last_seen":1790264662,"count":1,
	 "tags":"tlp:green,confidence:80","ttl":0,"consensus":2}

A value that is not there:

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/r/feeds/misp/ips?val=nope&noshadow'
	{"error":"Value not found","namespace":"feeds/misp/ips","value":"nope"}     # 404

A namespace that is not there:

	$ curl -H 'Authorization: changeme' 'http://127.0.0.1:9999/r/nosuch/namespace'
	{"error":"Path not found","namespace":"nosuch/namespace","value":""}       # 404

### `GET /r/<namespace>` — list a whole namespace

Omit `val`:

	$ curl -H 'Authorization: changeme' 'http://127.0.0.1:9999/r/feeds/misp/ips'
	{"attributes":[{"value":"1.2.3.4","first_seen":1790264378,"last_seen":1790264378,
	  "count":2,"tags":"stix-type:ipv4-addr,tlp:amber","ttl":0,"consensus":1}]}

### `GET /r/<namespace>?count` — how many values a namespace holds

Answers with the count instead of the values. Needs read access on the
namespace, the same as any other read.

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/r/feeds/misp/ips?count'
	{"namespace":"feeds/misp/ips","values":3,"exact":true,"paged_in":false}

This is O(1) — the value map already knows its own length, so nothing is
walked and the cost does not grow with the namespace. Listing the namespace to
count it, by contrast, builds and serializes every value.

**`exact` is the field to read.** It is `false` when the namespace has ever
held a value with a TTL:

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/r/feeds/expiring?count'
	{"namespace":"feeds/expiring","values":1,"exact":false,"paged_in":false}

A value stops being visible the moment it expires, but is only removed when
the sweeper next runs — every `sweep_interval` seconds, 60 by default. Nothing
fires at the moment of expiry, so between those two moments the stored count
is an **upper bound**. When `exact` is `false` and you need the visible number,
list the namespace and count what comes back, or read
`/_management/api/values` and take its `total`, both of which filter expired
values as they go.

The flag is sticky: a namespace that once held a TTL reports `exact: false`
afterwards even if that value has gone. It errs towards claiming less.

`paged_in` says whether answering had to read an evicted shard back into
memory. `false` means the answer came from memory alone.

Counting is not a search for a value, so it raises **no shadow sighting**.

`count` and `val` ask for different things, so asking for both is refused
rather than resolved silently:

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/r/feeds/misp/ips?val=1.2.3.4&count'
	{"message":"count applies to a namespace, not to one value. Drop val= to
	  count, or drop count to read the value."}                           # 400

A namespace that is not there:

	$ curl -H 'Authorization: changeme' 'http://127.0.0.1:9999/r/feeds/nothing?count'
	{"error":"Path not found","namespace":"feeds/nothing","value":""}     # 404

### Reading the shadow

A read without `noshadow` leaves a record of the search itself, which you can
then read like any other namespace — including for values that were never
there:

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/r/feeds/manual?val=unknown-thing'
	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/r/_shadow/feeds/manual?val=unknown-thing&noshadow'
	{"value":"unknown-thing","first_seen":1790265853,"last_seen":1790265853,
	 "count":1,"tags":"","ttl":2592000,"consensus":0}

The `ttl` is `shadow_ttl` from the configuration, which is what bounds
`_shadow/*` growth.

### `GET /rs/<namespace>?val=<value>` — read with hourly statistics

The same as `/r`, plus `stats`: a count per hour, keyed by the Unix timestamp
of the hour. `val` is required — a whole namespace has no statistics of its own.

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/rs/feeds/misp/ips?val=1.2.3.4&noshadow'
	{"value":"1.2.3.4","first_seen":1790264378,"last_seen":1790264378,"count":2,
	 "tags":"stix-type:ipv4-addr,tlp:amber","ttl":0,"consensus":1,
	 "stats":{"1790262000":2}}

### `GET /d/<namespace>` — delete a namespace

Removes the namespace and everything in it, giving back the consensus its
values were holding. Needs **write** access.

	$ curl -H 'Authorization: changeme' 'http://127.0.0.1:9999/d/feeds/misp/domains'
	{"message":"ok"}


Bulk
----

All four take the same item shape. `timestamp`, `ttl`, `tags` and `noshadow`
are optional per item.

	{"items": [
	  {"namespace": "feeds/misp/ips", "value": "1.2.3.4",
	   "timestamp": 1566624658, "ttl": 86400, "tags": "tlp:amber", "noshadow": true}
	]}

### `POST /wb` — record many sightings

Every item is authorized and recorded on its own, and `items` reports the
outcome of each in request order. **Read `items`, not the status code**, to
find out what happened to a given entry.

Everything accepted:

	$ curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/wb \
	    -d '{"items":[{"namespace":"feeds/misp/ips","value":"8.8.8.8"},
	                  {"namespace":"feeds/misp/domains","value":"bad.example","tags":"tlp:green"}]}'
	{"message":"ok","written":2,"items":[
	  {"index":0,"namespace":"feeds/misp/ips","value":"8.8.8.8","status":"ok","count":1},
	  {"index":1,"namespace":"feeds/misp/domains","value":"bad.example","status":"ok","count":1}]}

A successful item carries the value's resulting `count`, so no follow-up read
is needed. `index` is given explicitly, so an outcome maps back onto what you
sent even when the same value appears twice in one batch.

One bad item does not discard the rest:

	$ curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/wb \
	    -d '{"items":[{"namespace":"feeds/misp/ips","value":"9.9.9.9"},
	                  {"namespace":"feeds/misp/ips","value":""}]}'
	{"message":"partial","written":1,"items":[
	  {"index":0,"namespace":"feeds/misp/ips","value":"9.9.9.9","status":"ok","count":1},
	  {"index":1,"namespace":"feeds/misp/ips","value":"","status":"error",
	   "error":"Refusing to write an empty value."}],
	 "errors":[{"namespace":"feeds/misp/ips","value":"","error":"Refusing to write an empty value."}]}

An item the key may not write fails the same way as any other, and the rest
still lands. Here `feedwriter` holds `rw:feeds`:

	$ curl -H 'Authorization: feedwriter' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/wb \
	    -d '{"items":[{"namespace":"feeds/misp/ips","value":"7.7.7.7"},
	                  {"namespace":"secrets","value":"x"}]}'
	{"message":"partial","written":1,"items":[
	  {"index":0,"namespace":"feeds/misp/ips","value":"7.7.7.7","status":"ok","count":1},
	  {"index":1,"namespace":"secrets","value":"x","status":"error",
	   "error":"API key is not permitted to write this namespace."}],
	 "errors":[{"namespace":"secrets","value":"x",
	   "error":"API key is not permitted to write this namespace."}]}     # 200

When *every* item is refused, and only then, the request answers `403`:

	$ curl -H 'Authorization: analyst' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/wb \
	    -d '{"items":[{"namespace":"secrets","value":"x"}]}'
	{"message":"failed","written":0,"items":[
	  {"index":0,"namespace":"secrets","value":"x","status":"error",
	   "error":"API key is not permitted to write this namespace."}],
	 "errors":[...]}                                                      # 403

The status describes the batch as a whole:

| status | `message` | when |
| ------ | --------- | ---- |
| `200`  | `ok`      | every item landed |
| `200`  | `partial` | some landed, some did not |
| `403`  | `failed`  | nothing landed, and every item was refused |
| `400`  | `failed`  | nothing landed, for reasons that were not all refusals |

`errors` predates `items` and holds the failures alone; everything in it also
appears in `items`. It is omitted when there are none.

### `POST /vwb` — check a bulk write without recording it

A dry run of `/wb`. Same body, same status code, same per-item `status` and
`error` — and nothing is written. `message: ok` means the same batch sent to
`/wb` is accepted in full.

	$ curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/vwb \
	    -d '{"items":[{"namespace":"feeds/misp/ips","value":"1.1.1.1"}]}'
	{"message":"ok","writable":1,"items":[
	  {"index":0,"namespace":"feeds/misp/ips","value":"1.1.1.1","status":"ok"}]}

	$ curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/vwb \
	    -d '{"items":[{"namespace":"feeds/misp/ips","value":"1.1.1.1"},
	                  {"namespace":"feeds/misp/ips","value":""}]}'
	{"message":"partial","writable":1,"items":[
	  {"index":0,"namespace":"feeds/misp/ips","value":"1.1.1.1","status":"ok"},
	  {"index":1,"namespace":"feeds/misp/ips","value":"","status":"error",
	   "error":"Refusing to write an empty value."}],
	 "errors":[...]}

`writable` rather than `written`, because nothing was. Items carry no `count`
for the same reason.

Both routes decide each item with the same code, so the dry run cannot approve
something the writer then rejects. It is a **report, not a reservation**: the
ACL can be rewritten between the two calls, so a batch that validates can still
be refused when you write it. It also records nothing in the rejection log, and
leaves no sighting behind — which is the thing probing with a real write cannot
avoid.

### `POST /rb` — read many values

	$ curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/rb \
	    -d '{"items":[{"namespace":"feeds/misp/ips","value":"1.2.3.4","noshadow":true},
	                  {"namespace":"feeds/misp/ips","value":"nope","noshadow":true}]}'
	{"items":[
	  {"value":"1.2.3.4","first_seen":1790264378,"last_seen":1790264378,"count":2,
	   "tags":"stix-type:ipv4-addr,tlp:amber","ttl":0,"consensus":1},
	  {"error":"Value not found","namespace":"feeds/misp/ips","value":"nope"}]}

Results are positional: item *n* of the response answers item *n* of the
request, and a value that was not found appears as an error object in place of
an attribute.

### `POST /rbs` — read many values with statistics

	$ curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/rbs \
	    -d '{"items":[{"namespace":"feeds/misp/ips","value":"1.2.3.4","noshadow":true}]}'
	{"items":[{"value":"1.2.3.4","first_seen":1790264378,"last_seen":1790264378,
	  "count":2,"tags":"stix-type:ipv4-addr,tlp:amber","ttl":0,"consensus":1,
	  "stats":{"1790262000":2}}]}


STIX export
-----------

A read in another shape, so it needs read access and nothing more. What each
value becomes is driven by its tags — `stix-type:`, `tlp:`, `confidence:`,
`identity:`. See the README for the vocabulary.

### `GET /stix/<namespace>` — export one namespace

	$ curl -H 'Authorization: changeme' 'http://127.0.0.1:9999/stix/feeds/misp/ips'
	{"type":"bundle","id":"bundle--f121f63d-6579-5f6f-b43c-cf0eb223c448","objects":[
	  {"type":"identity","spec_version":"2.1","id":"identity--63f507d5-...",
	   "name":"SightingDB","identity_class":"system",
	   "created":"2017-01-20T00:00:00.000Z","modified":"2017-01-20T00:00:00.000Z"},
	  {"type":"indicator","spec_version":"2.1","id":"indicator--407cd7a8-...",
	   "pattern":"[ipv4-addr:value = '1.2.3.4']","pattern_type":"stix",
	   "created_by_ref":"identity--63f507d5-...",
	   "object_marking_refs":["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],
	   "valid_from":"2026-09-24T15:39:38.000Z", ...},
	  {"type":"sighting","spec_version":"2.1","id":"sighting--43ec94b4-...",
	   "count":2,"first_seen":"2026-09-24T15:39:38.000Z","last_seen":"2026-09-24T15:39:38.000Z",
	   "sighting_of_ref":"indicator--407cd7a8-...",
	   "where_sighted_refs":["identity--63f507d5-..."],
	   "x_sightingdb_namespace":"feeds/misp/ips", ...},
	  {"type":"marking-definition","spec_version":"2.1",
	   "id":"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
	   "name":"TLP:AMBER","definition_type":"tlp","definition":{"tlp":"amber"}}]}

Each value becomes an `indicator` plus a `sighting` that refers to it; the
namespace travels as `x_sightingdb_namespace`. A `tlp:` tag becomes a
`marking-definition` referenced from the objects it applies to.

`?limit=<n>` caps how many values go into the bundle — default 10000, clamped
to 100000. A bundle is read by a machine, but it is still one response held in
memory.

### Exporting a whole subtree

By default an export covers the one namespace named. `?recursive` (or
`"recursive": true` in the `POST` body) also takes every namespace below it:

	$ curl -D- -o /dev/null -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/stix/feeds'
	x-sightingdb-namespaces: 1
	x-sightingdb-exported: 1

	$ curl -D- -o /dev/null -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/stix/feeds?recursive'
	x-sightingdb-namespaces: 4
	x-sightingdb-exported: 4

`X-SightingDB-Namespaces` is how many namespaces contributed, so a caller that
named one can see it got a subtree and how big a one.

"Below" is a match on whole path segments. `feeds` finds `feeds` itself and
`feeds/misp/ips`, and never `feeds-internal` — which is a different namespace,
not a child.

**Permissions.** The namespace you name is authorized as always, so asking for
a subtree you may not read is a `403`:

	$ curl -o /dev/null -w '%{http_code}\n' -H 'Authorization: scoped' \
	    'http://127.0.0.1:9999/stix/feeds?recursive'
	403

What is *found* underneath follows the browsing rule instead: a namespace your
key may not read is left out rather than failing the export, exactly as it is
absent from the namespace tree. A key holding `rw:feeds/open` exporting
`/stix/feeds/open?recursive` gets its own subtree and nothing else.

**The limit is shared.** `limit=` is the budget for the whole export, not for
each namespace in it — per namespace it would multiply, and a recursive export
of a large tree would read a multiple of what was asked for:

	$ curl -D- -o /dev/null -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/stix/feeds?recursive&limit=2'
	x-sightingdb-namespaces: 2
	x-sightingdb-exported: 2
	x-sightingdb-truncated: true

`X-SightingDB-Truncated` says when the budget ran out with more to give, either
within a namespace or with namespaces still to go. Raise `limit=`, or export a
narrower part of the tree.

> **Changed behaviour.** `limit=` used to apply per namespace on
> `POST /_api/stix` with several namespaces named, so such a caller may now get
> fewer values than before for the same limit. The single-namespace case is
> unaffected.

`recursive` and `untyped` are independent, and combine.

### Values with no observable type

A STIX indicator *is* a pattern, and there is no pattern without a type. By
default a value whose type cannot be worked out — not an address, domain, URL,
hash or email address, and carrying no `stix-type:` tag — is left out and
counted:

	$ curl -D- -o /dev/null -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/_api/stix \
	    -d '{"namespace":"feeds/mixed","untyped":"skip"}'
	x-sightingdb-exported: 2
	x-sightingdb-skipped: 2
	x-sightingdb-untyped: 0

`untyped: include` (or `?untyped=include` on `GET /stix/<namespace>`) exports
them too:

	$ curl -D- -o /dev/null -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/_api/stix \
	    -d '{"namespace":"feeds/mixed","untyped":"include"}'
	x-sightingdb-exported: 4
	x-sightingdb-skipped: 0
	x-sightingdb-untyped: 2

Those go out as the custom observable `x-sightingdb-value`, each indicator
carrying `x_sightingdb_untyped: true`:

	{"type":"indicator", "pattern":"[x-sightingdb-value:value = 'whatever this is']",
	 "pattern_type":"stix", "x_sightingdb_untyped":true, ...}

**Why a custom type.** STIX 2.1 has no plain-text observable, and the
specification requires a custom type to carry an `x-` prefix. Naming our own
rather than borrowing something close — `artifact`, say — keeps the bundle
honest: a consumer is told this is a value SightingDB could not classify,
instead of being handed a pattern that claims something false about it. Read
`x_sightingdb_untyped` rather than matching on the type name, so filtering
does not depend on knowing it.

`skip` stays the default, so an existing caller's bundle does not change shape.

The better fix for a value you care about is to tell SightingDB what it is,
which also gets you a standard type instead of ours:

	$ curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/_management/api/tags \
	    -d '{"namespace":"feeds/mixed","value":"whatever this is","tags":"stix-type:x-threat-note, tlp:green"}'
	{"value":"whatever this is",...,"tags":"stix-type:x-threat-note,tlp:green",...}

It is then exported even in `skip` mode, under the type you gave it, and is
*not* counted as untyped — someone said what it was on purpose:

	   [x-threat-note:value = 'whatever this is'] | untyped flag: None

The management interface has a Tags column on the values list for exactly this,
and an Observable column beside it showing which values currently have no type.

### `POST /_api/stix` — export several namespaces into one bundle

Each namespace is authorized on its own, so a key scoped to one subtree cannot
widen its reach by naming another in the same request.

	$ curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/_api/stix \
	    -d '{"namespaces":["feeds/misp/ips"],"limit":1}'
	{"type":"bundle","id":"bundle--f121f63d-...","objects":[ ... ]}

`{"namespace": "feeds/misp/ips"}` is shorthand for a single one.


Storage
-------

### `POST /_api/tier` — set a namespace's tier

Tiers decide what stays in memory: `hot` is never evicted, `warm` is dropped
after `warm_idle` seconds untouched, `cold` is read in on demand.

Needs a key with an **admin** grant — it is the management interface's
`/_management/api/tier` under another name, not a data route. Internal
namespaces (those beginning with `_`) are always hot and cannot be retiered.

	$ curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/_api/tier \
	    -d '{"namespace":"feeds","tier":"warm"}'
	{"shard":"feeds","tier":"warm","warm_idle":3600,"own_tier":true,
	 "own_warm_idle":false,
	 "effect":"'feeds' and everything under it is dropped after 3600s untouched"}

`own_tier` says the tier was set on this namespace rather than inherited;
`own_warm_idle` likewise for the idle window. `effect` is the change in words.

This needs a `tiers_file` in `[storage]`, so the change survives a restart:

	{"message":"No tiers_file is configured, so tiers cannot be changed here.
	  Set tiers_file in [storage] and restart."}                          # 409


Service
-------

### `GET /health` — liveness and readiness

No key required.

	$ curl http://127.0.0.1:9999/health
	{"status":"ok","version":"0.5.9","uptime_seconds":8,"resident_shards":0,"shards":0}

`resident_shards` of `shards` is how much is in memory. A restored database
that has not been touched reports `0` of *n*, which is normal rather than ill.

### `GET /i` — implementation and version

No key required.

	$ curl http://127.0.0.1:9999/i
	{"implementation":"SightingDB","version":"0.5.9",
	 "vendor":"github.com/stricaud/sightingdb","author":"Sebastien Tricaud"}

### `GET /` — the route list

Anything that matches no other route answers this, as plain text.

	$ curl http://127.0.0.1:9999/
	SightingDB 0.5.9, written by Sebastien Tricaud
	REST Endpoints:
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
		/c: configure (GET)
		/i: info (GET)
		/health: liveness and readiness, no key required (GET)
		/_api/openapi.yaml: this API as an OpenAPI 3 document (GET)

### `GET /_api/openapi.yaml` — this API as an OpenAPI 3 document

	$ curl http://127.0.0.1:9999/_api/openapi.yaml -o sightingdb.yaml
	$ head -1 sightingdb.yaml
	openapi: "3.0.3"

The served copy has its `info.version` rewritten to whatever the server
actually is, so it cannot describe a release nobody is running. Import it into
Postman, Insomnia or Bruno.

### `GET /c/<namespace>` — not implemented

	$ curl -H 'Authorization: changeme' 'http://127.0.0.1:9999/c/feeds'
	{"message":"The /c endpoint is not implemented yet."}                 # 501


Management interface
--------------------

Everything under `/_management/` needs a key with an `admin` grant — always,
even when `authenticate = false`. Data routes are further scoped by the key's
own read and write grants, so an `admin, r:feeds` key browses `feeds/*` and
adds to nothing.

Out-of-reach namespaces answer **`404`, not `403`**, throughout this interface,
so that browsing cannot be used to enumerate what a key may not see.

`GET /_management` serves the browser interface itself (HTML, no key — the
interface asks for one and calls the API below).

### `GET /_management/api/session` — is this an admin key?

	$ curl -H 'Authorization: changeme' http://127.0.0.1:9999/_management/api/session
	{"message":"ok"}

### `GET /_management/api/info` — what this server was configured to do

	$ curl -H 'Authorization: changeme' http://127.0.0.1:9999/_management/api/info
	{"version":"0.5.9","authenticate":true,"http_enabled":true,
	 "config_path":"/etc/sightingdb/sightingdb.toml","dbdir":"/var/lib/sightingdb",
	 "snapshot_interval":300,"sweep_interval":60,"stats_retention":720,
	 "shadow_ttl":2592000,"dns":null,"zmq":null,
	 "namespaces":2,"apikeys":3,"default_tier":"hot","warm_idle":3600,"tiers":[]}

### `GET /_management/api/namespaces` — every namespace, paged

Takes `q` (case-insensitive substring), `offset`, `limit` (default 50, max 500).

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/_management/api/namespaces?limit=3'
	{"items":[{"namespace":"feeds/misp/ips","shard":"feeds","tier":"warm",
	  "resident":true,"warm_idle":3600,"own_tier":true,"own_warm_idle":false}],
	 "total":1,"offset":0}

### `POST /_management/api/namespaces` — create an empty namespace

Nothing else needs this — writing a value brings its namespace into being — but
a browser wants somewhere to put things before it has them.

	$ curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/_management/api/namespaces \
	    -d '{"namespace":"feeds/manual"}'
	{"namespace":"feeds/manual"}

Namespaces beginning with `_` are internal and are refused here.

### `GET /_management/api/tree` — one level of the namespace tree

Browses namespaces the way a file manager browses directories. Takes `path`,
`q`, `offset`, `limit`.

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/_management/api/tree?path=feeds'
	{"items":[{"name":"misp","path":"feeds/misp","is_namespace":false,
	  "descendants":1,"shard":"feeds","tier":"warm","resident":true,
	  "warm_idle":3600,"own_tier":true,"own_warm_idle":false}],
	 "total":1,"offset":0}

`is_namespace` distinguishes a node that holds values from one that is only a
path to others.

### `GET /_management/api/values` — the values in a namespace, paged

Statistics are omitted here because they are per value and can be large; the
detail view below fetches them one value at a time.

`total` is every value in the namespace, not just this page, and it excludes
expired values — so it is the visible count even where
[`/r/<namespace>?count`](#get-rnamespacecount--how-many-values-a-namespace-holds)
reports `exact: false`. It costs a walk of the namespace to produce, and an
admin key. Prefer `?count` unless you need the exactness or the values.

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/_management/api/values?namespace=feeds/misp/ips&limit=2'
	{"items":[
	  {"value":"1.2.3.4","first_seen":1790264378,"last_seen":1790264629,"count":4,
	   "tags":"stix-type:ipv4-addr,tlp:amber","ttl":0,"consensus":1},
	  {"value":"8.8.8.8","first_seen":1790264391,"last_seen":1790264391,"count":1,
	   "tags":"","ttl":0,"consensus":1}],
	 "total":3,"offset":0}

### `POST /_management/api/values` — add values to a namespace

For a pasted list. Blank lines are dropped before anything is tried.
`timestamp`, `ttl` and `tags` apply to every value in the request.

	$ curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/_management/api/values \
	    -d '{"namespace":"feeds/manual","values":["5.5.5.5","6.6.6.6","  "]}'
	{"namespace":"feeds/manual","written":2,
	 "counts":[{"value":"5.5.5.5","count":1},{"value":"6.6.6.6","count":1}]}

`counts` gives each value's running total afterwards. An `errors` array appears
if any value was rejected.

### `GET /_management/api/value` — one value, with its statistics

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/_management/api/value?namespace=feeds/misp/ips&value=1.2.3.4'
	{"value":"1.2.3.4","first_seen":1790264378,"last_seen":1790264629,"count":4,
	 "tags":"stix-type:ipv4-addr,tlp:amber","ttl":0,"consensus":1,
	 "stats":{"1790262000":4}}

### `GET /_management/api/sightings` — where else a value has been seen

The consensus relationship, spelled out: every namespace holding this value.

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/_management/api/sightings?namespace=feeds/misp/ips&value=1.2.3.4'
	{"value":"1.2.3.4","consensus":1,"paged_in":false,"truncated":false,
	 "items":[{"namespace":"feeds/misp/ips","shard":"feeds","count":4,
	   "first_seen":1790264378,"last_seen":1790264629}]}

`paged_in` says whether answering this had to read evicted shards back into
memory; `truncated` says the search stopped early.

### `POST /_management/api/tags` — replace a value's tags

This is **not** a sighting: nothing is counted and the seen window does not
move. It replaces outright, which is the only way a wrong tag comes off —
writes through `/w` and `/wb` merge instead.

	$ curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/_management/api/tags \
	    -d '{"namespace":"feeds/manual","value":"5.5.5.5","tags":"tlp:green,confidence:80"}'
	{"value":"5.5.5.5","first_seen":1790264662,"last_seen":1790264662,"count":1,
	 "tags":"tlp:green,confidence:80","ttl":0,"consensus":1}

### `GET /_management/api/rejections` — values that were not written

Every write path records what it turned away here — `/w`, `/wb`, this
interface, and the ZMQ ingest, which has no caller of its own to tell. It
answers "which values errored?" after the response that reported them has gone.

Takes `namespace` (a subtree, needing read access to it) and `limit`.

	$ curl -H 'Authorization: changeme' \
	    'http://127.0.0.1:9999/_management/api/rejections?limit=3'
	{"rejections":[
	  {"when":1790264662,"namespace":"feeds/manual","value":"",
	   "reason":"Refusing to write an empty value.","source":"bulkwrite"},
	  {"when":1790264662,"namespace":"secrets","value":"x",
	   "reason":"API key is not permitted to write this namespace.","source":"bulkwrite"}],
	 "total":2,"capacity":1000}

Newest first, filtered to what your key may read. `source` is `write` (`/w`),
`bulkwrite` (`/wb`), `management`, or `ingest`.

The record is **bounded and held in memory**. Once `total` reaches `capacity`
the oldest entries are being dropped, it does not survive a restart, and it is
kept out of snapshots, consensus and the STIX export — a value that was never
written has no business appearing there. It is for working out why a feed is
failing, not for audit. `rejection_log` in `[daemon]` resizes it; 0 switches it
off. `/vwb` records nothing here, since it writes nothing.

### `DELETE /_management/api/rejections` — forget them all

How an operator marks a feed as dealt with. All-or-nothing, so it needs a key
with unscoped read access.

	$ curl -H 'Authorization: changeme' -X DELETE \
	    http://127.0.0.1:9999/_management/api/rejections
	{"message":"ok"}

### `GET /_management/api/keys` — every key and what it may reach

	$ curl -H 'Authorization: changeme' http://127.0.0.1:9999/_management/api/keys
	[{"key":"analyst","admin":false,"read":["feeds"],"write":[]},
	 {"key":"changeme","admin":true,"read":[""],"write":[""]},
	 {"key":"feedwriter","admin":false,"read":["feeds"],"write":["feeds"]}]

An empty string in `read` or `write` means every namespace.

### `GET /_management/api/keys/generate` — a random key

Suggests one; it is not saved until you `POST` it back.

	$ curl -H 'Authorization: changeme' http://127.0.0.1:9999/_management/api/keys/generate
	{"key":"lT5iPqg8SVl8pJx6RtwfxeXUAmSjgnXM5DvbZngi"}

### `POST /_management/api/keys` — create or replace a key

	$ curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
	    -X POST http://127.0.0.1:9999/_management/api/keys \
	    -d '{"key":"reader","admin":false,"read":["feeds"],"write":[]}'
	{"key":"reader","admin":false,"read":["feeds"],"write":[]}

Takes effect immediately, without a restart, and is written back to `acl_file`.
Without an `acl_file` configured, keys are read-only and this answers `409`:
rewriting the daemon configuration in place is not something this does.

	{"message":"No acl_file is configured, so keys cannot be edited here.
	  Set acl_file in [daemon] and restart."}                             # 409

### `DELETE /_management/api/keys/<key>` — remove a key

	$ curl -H 'Authorization: changeme' -X DELETE \
	    http://127.0.0.1:9999/_management/api/keys/reader
	{"message":"ok"}

### `POST /_management/api/tier` — set a tier

The same handler as [`/_api/tier`](#post-_apitier--set-a-namespaces-tier)
above, under the management prefix. Both need an admin key; use whichever
reads better from the client you are writing.


Status codes
------------

| code | means |
| ---- | ----- |
| `200` | done |
| `400` | the request was malformed — no `val`, an empty value, a timestamp that is not an instant, unparseable JSON |
| `401` | no `Authorization` header, when `authenticate = true` |
| `403` | the key exists but may not reach this namespace, or `_config` was asked for |
| `404` | no such namespace or value — and, in the management interface, a namespace this key may not read |
| `409` | the server is not configured for this: no `acl_file` for a key change, no `tiers_file` for a tier change |
| `501` | `/c`, which is not implemented |

A refusal reads the same whether the key is unknown or merely out of scope, so
that probing cannot tell valid keys from invalid ones:

	$ curl 'http://127.0.0.1:9999/r/feeds/misp/ips?val=1.2.3.4&noshadow'
	{"message":"Please add the API key in the Authorization headers."}    # 401

	$ curl -H 'Authorization: analyst' 'http://127.0.0.1:9999/w/feeds/x?val=y'
	{"message":"API key is not permitted to write this namespace."}       # 403

The `_config` tree holds server state and is never reachable over HTTP — it is
what would let a key holder mint further keys for themselves.


See also
--------

- [openapi.yaml](openapi.yaml) — the same API as an OpenAPI 3 document, also
  served at `/_api/openapi.yaml`
- [../README.md](../README.md) — installation, configuration, tags and the STIX
  vocabulary, storage tiers, ZMQ ingest, DNS
