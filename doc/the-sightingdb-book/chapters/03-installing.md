# Installing

Three ways, in rising order of permanence: build it and run it, let `--setup`
install it, or run it in a container.

## Build it

SightingDB is a single Rust binary with no runtime dependencies beyond
OpenSSL.

```bash
git clone https://github.com/stricaud/sightingdb
cd sightingdb
cargo build --release
./target/release/sightingdb --help
```

To run it without installing anything:

```bash
./target/release/sightingdb -c etc/sightingdb.toml
```

`etc/sightingdb.toml` in the repository is a working configuration and is
mostly comments explaining itself. **Read the `dbdir` line before you run it**:
it points at `/var/lib/sighting`, which is where a real installation keeps its
data, and is probably not what you want for a first look.

## Let it install itself

```bash
sudo sightingdb --setup
```

This asks what the server is for and then writes everything: directories, a
configuration with comments, an API key, a self-signed certificate, and a
service for systemd or launchd. It asks before changing anything and tells you
what it did.

The first question is the one that matters:

```text
  1) standalone          stores everything; knows no peers
  2) node                stores namespaces; other servers forward to it
  3) router              stores nothing of its own; forwards to its peers
  4) both                stores some namespaces and forwards the rest
```

Chapter 8 is what those mean. If you are installing one server, it is 1.

What it writes, and which of them it will rewrite later:

| File | Who owns it |
| --- | --- |
| `sightingdb.toml` | **You.** Comment-rich, hand-maintained, never rewritten. |
| `acl.toml` | The program. Rewritten when a key is saved. |
| `tiers.toml` | The program. Rewritten when a storage tier changes. |
| `tags.toml` | The program. Rewritten when a tag's colour changes. |
| `peers.toml` | The program. Rewritten when a peer is added or changed. |

That split is the thing to understand about configuring SightingDB, and
chapter 4 is about it.

> `--setup` writes a **self-signed** certificate. It is there so that the first
> thing you run is encrypted rather than plaintext, not because it is good
> enough for a galaxy that crosses a network you do not control. Replace it, or
> terminate TLS in front.

## Run it in a container

```bash
docker compose -f docker/docker-compose.yml up --build
```

The image builds from your working tree, runs as a non-root user at a fixed
uid, and keeps its database on a named volume. The configuration baked in is
deliberately small — mount your own over `/etc/sightingdb/sightingdb.toml` to
change it, which is what the galaxy sample in `doc/docker` does.

Two environment variables matter:

| Variable | Effect |
| --- | --- |
| `SIGHTINGDB_APIKEY` | The key, granted full access. Read by the daemon itself, so it is not visible in `ps`. |
| `SIGHTINGDB_CONFIG` | Which configuration to read. |

## Kubernetes

```bash
make deploy        # into the cluster kubectl already points at
make dev           # into a kind cluster this creates for the purpose
```

Both build the image from your tree, install the Helm chart, wait for the pod
and write a sighting through it to prove it works. **They refuse to touch a
cluster that is not local** — they check the context against a list of local
ones and stop otherwise, because a `kubectl config use-context` away from
production should not be one keystroke away from `make deploy`.

`make port-forward` and `make admin-key` then get you into the interface.

## Checking it started

```bash
curl -fsS http://localhost:9999/health
```

```json
{"status":"ok","version":"0.7.1","uptime_seconds":12,
 "resident_shards":2,"shards":2,"catching_up":false}
```

`/health` needs no key, which is what makes it usable as a container
healthcheck and a load balancer probe. Everything else needs one.

If it did not start, it said why and exited; look at `log_err` from the
configuration, or the container's logs. A configuration that will not parse
names the line.
