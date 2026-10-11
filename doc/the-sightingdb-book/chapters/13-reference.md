# Reference

The short version of everything, for finding rather than reading.

## Routes

| Route | Method | What it does |
| --- | --- | --- |
| `/w/<namespace>?val=` | GET | Record a sighting. |
| `/wb` | POST | Record many. |
| `/vwb` | POST | Check a batch without recording it. |
| `/r/<namespace>?val=` | GET | Read one value. |
| `/r/<namespace>` | GET | List a namespace. |
| `/r/<namespace>?count` | GET | How many values it holds. |
| `/rs/<namespace>?val=` | GET | Read with hourly statistics. |
| `/rb`, `/rbs` | POST | Read many, without and with statistics. |
| `/d/<namespace>` | GET | Delete a whole namespace. |
| `/stix/<namespace>` | GET | Export as a STIX 2.1 bundle. |
| `/_api/stix` | POST | Export several namespaces into one bundle. |
| `/_api/merge` | POST | Fold a peer's copy of values into ours. |
| `/_api/namespaces` | GET | What this server actually stores. |
| `/_api/tier` | POST | Set a namespace's tier. |
| `/_api/openapi.yaml` | GET | The whole API as OpenAPI 3. |
| `/health` | GET | Liveness. No key needed. |
| `/i` | GET | Version and implementation. |
| `/` | GET | The route list. No key needed. |

Management, all under `/_management/api/`:

| Route | Method | What it does |
| --- | --- | --- |
| `session` | GET | Is this an admin key? |
| `info` | GET | What this server was configured to do. |
| `namespaces` | GET, POST | List, or create an empty one. |
| `tree` | GET | One level of the namespace tree. |
| `values`, `value` | GET | Values in a namespace; one value. |
| `sightings` | GET | Where else a value has been seen. |
| `tags` | GET, POST | The vocabulary; replace a value's tags. |
| `tags/vocabulary` | POST, DELETE | Define or forget a tag's colour. |
| `galaxy` | GET | The whole cascade, for drawing. |
| `galaxy/peers` | GET, POST, PUT, DELETE | List, add, change, remove a peer. |
| `galaxy/peers/enabled` | POST | Take a peer out of service, or back. |
| `keys` | GET, POST, PUT | List, save, or replace the whole list. |
| `keys/generate` | GET | A random key. |
| `keys/drift` | GET | Where this server's keys and its peers' disagree. |
| `keys/<key>` | DELETE | Remove a key. |
| `rejections` | GET, DELETE | What was refused; forget it. |
| `tier` | POST | Set a tier. |

`doc/routes.md` has every one of these with a worked example and its status
codes. A test keeps it from drifting.

## Query parameters

| Parameter | On | Effect |
| --- | --- | --- |
| `val=` | `/w`, `/r`, `/rs` | The value. |
| `noshadow` | reads | Do not record that somebody searched. |
| `timestamp=` | `/w` | Unix seconds; record it as seen then. |
| `ttl=` | `/w` | Seconds until it stops being visible. |
| `tags=` | `/w` | Tags to merge in. |
| `count` | `/r` | Answer with the number of values instead. |
| `for_merge` | `/r` | The per-node shape a peer is offered. |
| `recursive` | `/stix` | Include the namespaces below this one. |
| `untyped=include` | `/stix` | Export values with no observable type. |
| `limit=`, `q=` | listings, `/stix` | Page size; substring filter. |

## Status codes

| Code | Meaning |
| --- | --- |
| `200` | Done. A batch may be `partial`; read `items`. |
| `400` | Malformed, or a batch that failed for mixed reasons. |
| `401` | No key. |
| `403` | Not permitted, or a write to an internal namespace. |
| `404` | No such namespace, or no such value in it. |
| `409` | Refused because of how things are configured. |
| `421` | Nowhere in reach stores that namespace. |
| `500` | Something broke. |
| `502` | A mirror that holds it could not be reached. |
| `508` | A forwarded request ran out of hops. |

## Configuration at a glance

| Section | Setting | Default |
| --- | --- | --- |
| `[daemon]` | `listen_ip`, `listen_port` | `127.0.0.1`, `9999` |
| | `authenticate` | `true` |
| | `ssl`, `ssl_cert`, `ssl_key` | off |
| | `dbdir` | none — **nothing persists without it** |
| | `snapshot_interval` | `300` |
| | `sweep_interval` | `60` |
| | `stats_retention` | `720` hours |
| | `shadow_ttl` | `2592000` seconds |
| | `post_limit` | 2.5 GB |
| | `rejection_log` | `1000` |
| | `node_id` | `"local"` — **unique per server in a galaxy** |
| | `acl_file`, `tags_file` | none |
| `[storage]` | `namespaces` | everything |
| | `default_tier`, `warm_idle` | `hot`, `3600` |
| | `tiers_file` | none |
| `[galaxy]` | `peers`, `peers_file` | none |
| | `max_hops` | `4` |
| | `health_interval` | `30` |
| | `sync_interval` | `300` |
| | `reconcile_interval` | `3600` |
| | `gossip_interval` | `600` |
| | `acl_authority`, `acl_replaceable` | `false` |
| | `verify_tls` | `true` |
| `[stix]` | `identity`, `identity_class` | `SightingDB`, `system` |
| `[zmq]` | `url`, `format`, `types` | none |
| `[dns]` | `listen`, `zone`, `ttl` | none |

## The files

| File | Owner | Rewritten when |
| --- | --- | --- |
| `sightingdb.toml` | you | never |
| `acl_file` | the program | a key is saved |
| `tiers_file` | the program | a tier changes |
| `tags_file` | the program | a tag's colour changes |
| `peers_file` | the program | a peer is added, changed or disabled |

## Internal namespaces

| Namespace | What it is | Readable | Writable |
| --- | --- | --- | --- |
| `_all` | The consensus tally. | yes | **no** |
| `_shadow/<ns>` | What was searched for in `<ns>`. | yes | no |
| `_config` | Server state. | no | no |

Nothing beginning with `_` is writable from outside, at any permission level.
A client that could write `_all` could forge consensus.

## The Python client

| Call | Does |
| --- | --- |
| `write(ns, value, timestamp=, ttl=)` | One sighting. Returns the count. |
| `write_many(sightings, strict=)` | A batch. |
| `batch(chunk_size=)` | A self-flushing batch, as a context manager. |
| `read(ns, value, stats=, shadow=)` | One value. |
| `read_many(sightings, stats=)` | Many, positionally. |
| `exists(ns, value, shadow=)` | Has this ever been seen? |
| `list_values(ns)` | Every value in a namespace. |
| `delete(ns, missing_ok=)` | A whole namespace. |
| `info()`, `ping()`, `close()` | Version; liveness; done. |

`AsyncSightingDB` is the same with `await`.

## Where else to look

| | |
| --- | --- |
| `README.md` | The repository's own tour, in more depth on some things. |
| `doc/routes.md` | Every route, with examples and status codes. |
| `doc/ADDING-NEW-NODE.md` | Joining a node to a galaxy, with troubleshooting. |
| `doc/docker/` | A four-container galaxy to try things on. |
| `doc/openapi.yaml` | The API as a machine-readable document. |
| `etc/sightingdb.toml` | Every setting, with the reasoning beside it. |
