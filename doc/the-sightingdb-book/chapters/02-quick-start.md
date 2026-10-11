# Quick start

Five minutes, one container, no configuration.

## Run it

From a clone of the repository:

```bash
docker compose -f docker/docker-compose.yml up --build
```

That builds the image from the source in your working tree and starts one
server on port 9999 with the API key `changeme`.

> There is no published image to pull. SightingDB is small and builds in a
> couple of minutes, and an image you built from the source in front of you is
> one fewer thing to trust.

If you would rather not use Docker, chapter 3 builds it directly; everything
below is the same either way.

## Write a sighting

```bash
curl -H 'Authorization: changeme' \
  'http://localhost:9999/w/feeds/ips?val=198.51.100.23'
```

```json
{"message":"ok","count":1,"new":true}
```

Run it again. And again.

```json
{"message":"ok","count":3,"new":false}
```

`new` is whether this namespace had ever seen the value before, which is the
one thing you cannot work out from the count afterwards.

## Read it back

```bash
curl -H 'Authorization: changeme' \
  'http://localhost:9999/r/feeds/ips?val=198.51.100.23&noshadow'
```

```json
{"value":"198.51.100.23","first_seen":1791668207,"last_seen":1791668230,
 "count":3,"tags":"","ttl":0,"consensus":1}
```

`noshadow` is there because **a read is itself an observation**. Without it,
SightingDB records that somebody asked — in a parallel `_shadow/` namespace —
which is how you find out which indicators your analysts keep looking up. When
you are reading your own data in a loop, say `noshadow` and it records nothing.

## Write a lot of them at once

One sighting per HTTP request is fine for enrichment, and wrong for ingest:

```bash
curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
  -X POST http://localhost:9999/wb -d '{"items":[
    {"namespace":"feeds/ips","value":"198.51.100.23","tags":"tlp:green"},
    {"namespace":"feeds/ips","value":"203.0.113.7"},
    {"namespace":"feeds/domains","value":"login.phish.example"}
  ]}'
```

Every item gets its own result, so one bad value does not discard the batch:

```json
{"message":"ok","written":3,"items":[
  {"index":0,"namespace":"feeds/ips","value":"198.51.100.23","status":"ok",
   "count":4,"new":false}, ...]}
```

## Open the interface

<http://localhost:9999/_management>, with the key `changeme`.

![The namespace tree. A path is a folder and a namespace at once.](images/ui-browse.png){width=100%}

## Try it from Python

```bash
pip install sightingdb-client
```

```python
from sightingdb import SightingDB

db = SightingDB(url="http://localhost:9999", apikey="changeme")

db.write("feeds/ips", "198.51.100.23")
print(db.read("feeds/ips", "198.51.100.23", shadow=False).count)
print(db.exists("feeds/ips", "203.0.113.99"))
```

Chapter 7 is the rest of it.

## A galaxy, if you want one now

One server is a node. Several servers behind a load balancer is a *galaxy*, and
there is a four-container sample of one:

```bash
docker compose -f doc/docker/docker-compose.yml up --build
```

That starts a load balancer on 9999 and three nodes — two full mirrors and one
holding a single namespace — and loads them with real indicators from CIRCL's
public OSINT feed. Chapter 8 explains what it is doing; `doc/docker/README.md`
lists things to try.

## What to read next

- **Chapter 3** to install it properly, with TLS and a service.
- **Chapter 4** for the configuration files.
- **Chapter 5** for the rest of the API.
- **Chapter 8** if you are here because one server is not enough.
