#!/bin/sh
# Runs SightingDB in the foreground as PID 1's child, so a stop signal reaches
# it and the database is snapshotted on the way out.
#
# Everything here is a *default*: an option the caller already gave is left
# alone. Kubernetes passes its own -c and -l, and clap treats an option given
# twice as an error rather than an override.
set -eu

given() {
    short=$1
    long=$2
    shift 2
    for arg in "$@"; do
        case "$arg" in
            "$short" | "$long" | "$long"=*) return 0 ;;
        esac
    done
    return 1
}

if ! given -c --config "$@"; then
    set -- -c "${SIGHTINGDB_CONFIG:-/etc/sightingdb/sightingdb.toml}" "$@"
fi

if [ -n "${SIGHTINGDB_LOG_CONFIG:-}" ] && ! given -l --logging-config "$@"; then
    set -- -l "$SIGHTINGDB_LOG_CONFIG" "$@"
fi

# Kept for the docker-compose file and anyone who was using it: a key given
# this way replaces the built-in one.
if [ -n "${SIGHTINGDB_APIKEY:-}" ] && ! given -k --apikey "$@"; then
    set -- -k "$SIGHTINGDB_APIKEY" "$@"
fi

exec sightingdb "$@"
