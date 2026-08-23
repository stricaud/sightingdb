# syntax=docker/dockerfile:1
#
# Builds the source in this working tree, not a clone of the repository, so
# `make image` packages what you are actually looking at.
#
# Build from the repository root:
#     docker build -f docker/Dockerfile -t sightingdb:dev .

ARG RUST_VERSION=1
ARG DEBIAN_VERSION=bookworm

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS build

# OpenSSL is linked dynamically by default; build with FEATURES=vendored-openssl
# to compile it in instead, which costs several minutes and needs no libssl on
# the runtime image.
ARG FEATURES=""

RUN apt-get update -q \
 && apt-get install -qy --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# The registry and target directories are cache mounts, so a rebuild after a
# one-line change does not start from nothing. Nothing in a cache mount is kept
# in the layer, which is why the binary is copied out inside the same step.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
      $(test -n "$FEATURES" && echo "--features $FEATURES") \
 && cp target/release/sightingdb /usr/local/bin/sightingdb

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
FROM debian:${DEBIAN_VERSION}-slim

LABEL org.opencontainers.image.title="SightingDB" \
      org.opencontainers.image.description="A database designed for Sightings" \
      org.opencontainers.image.source="https://github.com/stricaud/sightingdb" \
      org.opencontainers.image.licenses="MIT"

# curl is here on purpose: the Helm chart's bootstrap job and its test both
# talk to the API, and using this image for them means no second image to pull
# in a cluster that cannot reach a registry.
RUN apt-get update -q \
 && apt-get install -qy --no-install-recommends ca-certificates libssl3 curl \
 && rm -rf /var/lib/apt/lists/*

# A user of its own, at a fixed uid: the Helm chart's fsGroup has to name it,
# and a volume whose owner changes between releases is a bad afternoon.
#
# The daemon is *started* as this user and never runs as root — it has no
# setuid of its own and needs none, since nothing it opens is privileged. A
# port below 1024 is the one exception, and that is a capability
# (CAP_NET_BIND_SERVICE) rather than a reason to start as root.
#
# The data directory is owned by group 0 and group-writable as well, so the
# image also works where the uid is assigned rather than chosen — OpenShift
# runs containers under a random uid in group 0.
RUN groupadd --gid 10001 sightingdb \
 && useradd --uid 10001 --gid 10001 --home-dir /var/lib/sightingdb --no-create-home sightingdb \
 && mkdir -p /etc/sightingdb /var/lib/sightingdb \
 && chown -R 10001:0 /var/lib/sightingdb \
 && chmod -R g=u /var/lib/sightingdb

COPY --from=build /usr/local/bin/sightingdb /usr/local/bin/sightingdb
# A configuration that works out of the box for `docker run`. Kubernetes mounts
# its own over the top; see helm/sightingdb.
COPY docker/sightingdb.toml /etc/sightingdb/sightingdb.toml
COPY docker/sightingdb-entrypoint.sh /usr/local/bin/sightingdb-entrypoint.sh

USER 10001:10001
WORKDIR /var/lib/sightingdb
VOLUME ["/var/lib/sightingdb"]
EXPOSE 9999

# Tries plain HTTP first, then TLS, because whether the daemon terminates TLS
# is a matter of the configuration mounted over this one. A container on a
# different port wants `docker run --health-cmd` to say so.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:9999/health \
   || curl -fsSk https://127.0.0.1:9999/health \
   || exit 1

ENTRYPOINT ["/usr/local/bin/sightingdb-entrypoint.sh"]
