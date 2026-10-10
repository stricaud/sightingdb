#!/bin/sh
# Demo data for the galaxy in docker-compose.yml.
#
# The indicators come from CIRCL's public MISP OSINT feed, converted by
# fetch-demo-data.py into the shape SightingDB's own MISP ingest would have
# produced — same namespaces, same tags. See demo-data.json, whose `_source`
# records which event it came from, and the header of fetch-demo-data.py.
#
# They are someone else's published observations, kept here only so the demo
# has something real in it. Nothing is asserted about them.
#
# Everything is written **through the load balancer**, which is the point: each
# sighting lands on the nodes that hold its namespace, and is counted once
# rather than once per mirror. Writing into the nodes directly would produce a
# galaxy that looks right and counts wrong.
set -eu

SIGHTINGDB="${SIGHTINGDB:-http://lb:9999}"
APIKEY="${APIKEY:-demo}"
DATA="${DATA:-/demo-data.json}"
PICKS="${PICKS:-/demo-data.env}"

api() {
    method=$1
    path=$2
    shift 2
    curl -fsS -X "$method" "$SIGHTINGDB$path" \
        -H "Authorization: $APIKEY" \
        -H 'Content-Type: application/json' "$@"
}

echo "Seeding $SIGHTINGDB from $DATA"

# ---------------------------------------------------------------------------
# Join the nodes to the galaxy
# ---------------------------------------------------------------------------
#
# Through the API rather than by listing them in lb.toml, so they belong to the
# load balancer's peers_file and stay **editable under Galaxy** in the
# interface: the key a node is reached with, the namespaces it holds, and
# whether it is there at all. A peer written into the configuration shows up
# the same but read-only, since that file is not ours to rewrite.
#
# This is exactly what doc/ADDING-NEW-NODE.md describes, so the demo exercises
# the path it documents.
#
# Each key is the narrowest thing that works there, which is the point of a
# peer key: node-c gives this load balancer misp/ips and nothing else, and it
# is node-c that enforces it.
join() {
    # 409 means it is already a peer, which is the normal case on a restart:
    # peers_file survives, so only a fresh volume needs this.
    status=$(curl -s -o /tmp/join.json -w '%{http_code}' \
        -X POST "$SIGHTINGDB/_management/api/galaxy/peers" \
        -H "Authorization: $APIKEY" -H 'Content-Type: application/json' \
        -d "$1")
    case "$status" in
        200) echo "  joined $2" ;;
        409) echo "  $2 is already in the galaxy" ;;
        *)   echo "  COULD NOT JOIN $2: HTTP $status $(cat /tmp/join.json)" ; exit 1 ;;
    esac
}

join '{"url":"http://node-a:9999","key":"lb-full"}' "node-a (full mirror)"
join '{"url":"http://node-b:9999","key":"lb-full"}' "node-b (full mirror)"
join '{"url":"http://node-c:9999","key":"lb-ips","namespaces":["misp/ips"]}' \
     "node-c (misp/ips only)"

# ---------------------------------------------------------------------------
# The feed itself
# ---------------------------------------------------------------------------
#
# One bulk write. The load balancer fans it out and answers per item, so a
# namespace no node holds is reported against that item rather than failing the
# batch. The `_source` block in the file is not a field the API knows; it is
# ignored, which is what keeps the provenance in the same file as the data.
api POST /wb --data-binary "@$DATA" > /tmp/seeded.json
written=$(sed -n 's/.*"written":\([0-9]*\).*/\1/p' /tmp/seeded.json)
echo "  wrote $written sighting(s) across misp/ips, misp/domains, misp/urls, misp/hashes, misp/files"

# Which node took what. node-c holds only misp/ips, so the rest went to node-a
# and node-b alone.
echo "  (node-c holds misp/ips only; the other namespaces live on node-a and node-b)"

# ---------------------------------------------------------------------------
# Seen again, so there is a count and a histogram rather than a single bar
# ---------------------------------------------------------------------------
#
# This is what SightingDB is for: not "is this bad" but "how often, and when".
# The feed gives one observation per indicator, all at the event's timestamp;
# these are further sightings of one of them, now.
. "$PICKS"
i=1
while [ "$i" -le 11 ]; do
    api GET "/w/$REPEAT_NAMESPACE?val=$REPEAT_VALUE" > /dev/null
    i=$((i + 1))
done
echo "  $REPEAT_NAMESPACE $REPEAT_VALUE: seen 12 times now, not once"

# ---------------------------------------------------------------------------
# The same value in a second namespace, so consensus is 2
# ---------------------------------------------------------------------------
#
# Consensus is how many namespaces have seen a value at all — a different
# question from how often. A load balancer keeps that tally itself, because no
# single node can answer it.
api POST /wb -d "{\"items\":[
  {\"namespace\":\"watchlist/ips\",\"value\":\"$REPEAT_VALUE\",
   \"tags\":\"stix-type:ipv4-addr,tlp:green,needs-review\"}
]}" > /dev/null
echo "  watchlist/ips $REPEAT_VALUE: the same value in a second namespace (consensus 2)"

# ---------------------------------------------------------------------------
# A tag fixed after the fact, which the mirrors have to agree about
# ---------------------------------------------------------------------------
#
# This replaces the set rather than adding to it, and the answer names the
# mirrors that took it. It is the one kind of change that is not a sighting, so
# nothing in the sync machinery would otherwise carry it to them.
api POST /_management/api/tags -d "{
  \"namespace\":\"$REPEAT_NAMESPACE\",\"value\":\"$RETAG_VALUE\",
  \"tags\":\"stix-type:ipv4-addr,tlp:amber,indicator-type:malicious-activity,reviewed-by:demo\"
}" > /tmp/retagged.json
mirrors=$(tr ',' '\n' < /tmp/retagged.json | grep -c '"ok":true' || true)
echo "  $REPEAT_NAMESPACE $RETAG_VALUE: retagged, accepted by $mirrors mirror(s)"

cat <<EOF

Done. Open http://localhost:9999/_management and sign in with: $APIKEY

  Browse     misp/ips, misp/domains, misp/urls, misp/hashes, watchlist/ips
  Tags       the feed's own MISP machine tags. tlp: is coloured; the
             misp-galaxy:, osint: and type: families are listed as seen but
             not defined, one click from being adopted
  Galaxy     three nodes, their health, and which hold everything
  A value    open $REPEAT_VALUE in $REPEAT_NAMESPACE for its history

Export what the feed gave you, back out as STIX 2.1:

  curl -H 'Authorization: $APIKEY' 'http://localhost:9999/stix/misp/domains'
EOF
