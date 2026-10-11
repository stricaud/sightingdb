# The Python client

```bash
pip install sightingdb-client
```

Python 3.10 or newer. The source is at
`github.com/stricaud/sightingdb-client`.

## Connecting

```python
from sightingdb import SightingDB

db = SightingDB(url="https://sightingdb.example:9999", apikey="changeme")
```

Or from the environment, which is what you want in anything scheduled:

```bash
export SIGHTINGDB_URL=https://sightingdb.example:9999
export SIGHTINGDB_APIKEY=changeme
```

```python
db = SightingDB()
```

Or from `~/.config/sightingdb/client.toml`. `client.toml.example` in the
repository is the template. For a self-signed certificate, `verify=False`.

## Writing

```python
db.write("feeds/misp/ips", "198.51.100.23")
```

Returns the new count. Timestamps and TTLs are `datetime` and `timedelta`
rather than seconds, because that is what your code already has:

```python
from datetime import datetime, timedelta, timezone

db.write("feeds/misp/ips", "203.0.113.7",
         timestamp=datetime(2026, 3, 1, tzinfo=timezone.utc),
         ttl=timedelta(days=30))
```

## Writing a lot

One call per sighting is one HTTP request per sighting. For ingest, batch:

```python
from sightingdb import Sighting

result = db.write_many([
    Sighting("feeds/misp/ips", "198.51.100.23", ttl=timedelta(days=7)),
    ("feeds/misp/ips", "203.0.113.7"),
    {"namespace": "feeds/misp/domains", "value": "login.phish.example"},
])

print(result.written, "written")
for failure in result.errors:
    print(failure.namespace, failure.value, failure.error)
```

Three shapes are accepted because three shapes are what callers have: a
`Sighting`, a tuple, or the dict you already decoded from somewhere.

`strict=True` — the default — raises if anything was refused. `strict=False`
returns the result and lets you decide, which is usually what a feed importer
wants: one bad value out of fifty thousand should not stop the import.

For a stream that never ends, a batch flushes itself:

```python
with db.batch(chunk_size=5000) as batch:
    for namespace, value in every_line_of_the_feed():
        batch.add(namespace, value)
```

## Reading

```python
seen = db.read("feeds/misp/ips", "198.51.100.23", shadow=False)

print(seen.count)
print(seen.first_seen_at, seen.last_seen_at)   # datetimes
print(seen.tags)
print(seen.consensus)
```

`shadow=False` is `noshadow` from chapter 5: it stops the read being recorded
as a search. **Pass it whenever you are reading your own data**, and leave it
alone when the read represents an analyst actually asking.

Hourly statistics on request:

```python
seen = db.read("feeds/misp/ips", "198.51.100.23", stats=True, shadow=False)
for hour, count in seen.stats_by_hour.items():
    print(hour, count)
```

Many at once, positionally:

```python
results = db.read_many([
    Sighting("feeds/misp/ips", "198.51.100.23", noshadow=True),
    Sighting("feeds/misp/ips", "203.0.113.99", noshadow=True),
])

for result in results:
    if result.found:
        print(result.value, result.count)
    else:
        print(result.value, "not seen")
```

And the question you will ask most:

```python
if not db.exists("feeds/misp/ips", address, shadow=False):
    alert("first time we have ever seen this")
```

## The rest

```python
db.list_values("feeds/misp/ips", shadow=False)   # every value, as Attributes
db.delete("feeds/misp/ips", missing_ok=True)     # the whole namespace
db.info()                                         # version, what it stores
db.ping()                                         # is it there
db.close()
```

`SightingDB` is a context manager, so `with SightingDB() as db:` closes the
connection for you.

## Asynchronously

`AsyncSightingDB` has the same API with `await`:

```python
from sightingdb import AsyncSightingDB

async with AsyncSightingDB(url=..., apikey=...) as db:
    await db.write("feeds/misp/ips", "198.51.100.23")
    seen = await db.read("feeds/misp/ips", "198.51.100.23", shadow=False)
```

## Talking to several servers

A client can point at a load balancer — chapter 8 — and nothing changes. It can
also fan out itself, which is useful when you would rather not run one:

```python
db = SightingDB(
    urls=["https://node-a.example:9999", "https://node-b.example:9999"],
    apikey="changeme",
)
```

Writes then go to **every** node and reads to **one**. Two things make that
correct rather than merely parallel, and both are easy to get wrong.

**A fanned-out write is attributed to its origin.** SightingDB counts sightings
per server so that merging two copies adds separate contributions rather than
replaying increments. One write sent to two nodes would otherwise be counted by
each under its own name, and when those nodes sync, three writes would become
six. So the client names itself in a header and every node counts the write
under that one name.

**A value always reads from the same node.** Nodes drift apart transiently
while they catch up with each other, so two consecutive reads served by
different nodes could show a count going *down*. The client picks the node by
hashing the value, which also moves the fewest values when the node list
changes.

```python
db.fans_out      # True when there is more than one
db.urls          # what it is pointing at
```

With one URL none of this happens: no extra headers, no hashing. Pointing at
one server behaves exactly as it did before any of this existed.

## A worked example

Enrich a stream of addresses, recording each as seen and reporting the new
ones:

```python
from datetime import timedelta
from sightingdb import SightingDB, Sighting

with SightingDB() as db:
    addresses = [line.strip() for line in open("today.txt")]

    # One round trip to find out which are new...
    before = {
        result.value: result.found
        for result in db.read_many(
            [Sighting("myorg/proxy/ips", a, noshadow=True) for a in addresses]
        )
    }

    # ...and one to record them all.
    db.write_many(
        [Sighting("myorg/proxy/ips", a, ttl=timedelta(days=90)) for a in addresses],
        strict=False,
    )

    for address in addresses:
        if not before.get(address):
            print("first sighting:", address)
```

Two requests for the whole file, rather than two per address.
