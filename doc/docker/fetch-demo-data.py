#!/usr/bin/env python3
"""Turn a MISP event from CIRCL's public OSINT feed into SightingDB demo data.

The output is `demo-data.json`, a `/wb` body that `seed.sh` posts through the
load balancer. It is committed so the demo works offline and shows the same
thing every time; run this to refresh it or to pick a different event.

    python3 doc/docker/fetch-demo-data.py                 # the default event
    python3 doc/docker/fetch-demo-data.py --uuid <uuid>    # another one
    python3 doc/docker/fetch-demo-data.py --list           # what is available

**The mapping here mirrors `src/ingest/misp.rs`**, which is what SightingDB's
ZMQ ingest does with a live MISP feed: the namespace comes from the attribute
type, and the tags are `misp-type:`, `stix-type:`, `misp-category:`,
`misp-event:`, `description:` and MISP's own tags carried across as published.
So the demo data is shaped like data that really arrived from MISP, rather than
like something invented for a screenshot.

That includes carrying down the tags on the *event* — which is where CIRCL puts
the TLP marking — exactly as the ingest does, with the attribute's own marking
winning where the two would contradict each other.
"""

import argparse
import datetime
import json
import sys
import urllib.request

FEED = "https://www.circl.lu/doc/misp/feed-osint"

# The feed is not uniformly public. A snapshot of today's manifest had 1296
# events tagged tlp:white and 415 tlp:clear — but also 76 tlp:green, one
# tlp:amber, and 21 with no TLP tag at all. Green means "the community, not the
# world"; those are near-certainly publication slips, and they are exactly what
# must not end up committed to a public repository.
#
# So an event is converted only if it says it may be shared without
# restriction, and `--force` is the only way past that.
PUBLIC_TLP = {"tlp:white", "tlp:clear"}

# CIRCL republishes other people's analysis as well as its own, and the feed
# preserves who each event came from. Restricting the default to CIRCL's own
# events keeps the provenance of anything committed here to one organisation.
PREFERRED_ORG = "CIRCL"

# A multi-stage campaign write-up: domains, hashes, addresses and URLs in one
# event, which is what makes it show namespace routing rather than one big list
# of the same kind of thing.
DEFAULT_EVENT = "cf909fc3-0e55-4962-b462-2219981ea53c"

# MISP attribute type to namespace. Spread across several namespaces on purpose:
# in the galaxy this feeds, node-c holds only `misp/ips`, so where a value
# lands is visible.
NAMESPACES = {
    "ip-src": "misp/ips",
    "ip-dst": "misp/ips",
    "ip-src|port": "misp/ips",
    "ip-dst|port": "misp/ips",
    "domain": "misp/domains",
    "hostname": "misp/domains",
    "domain|ip": "misp/domains",
    "url": "misp/urls",
    "uri": "misp/urls",
    "link": "misp/urls",
    "md5": "misp/hashes",
    "sha1": "misp/hashes",
    "sha256": "misp/hashes",
    "filename|md5": "misp/hashes",
    "filename|sha1": "misp/hashes",
    "filename|sha256": "misp/hashes",
    "email": "misp/emails",
    "email-src": "misp/emails",
    "email-dst": "misp/emails",
    "filename": "misp/files",
    "mutex": "misp/mutexes",
    "regkey": "misp/regkeys",
    "mac-address": "misp/macs",
    "AS": "misp/asns",
    "vulnerability": "misp/vulnerabilities",
}

# Exactly `stix_type_for_misp` in src/ingest/misp.rs. Anything absent keeps its
# `misp-type:` tag and the export falls back to the shape of the value.
STIX_TYPES = {
    "ip-src": "ipv4-addr",
    "ip-dst": "ipv4-addr",
    "ip-src|port": "ipv4-addr",
    "ip-dst|port": "ipv4-addr",
    "domain": "domain-name",
    "hostname": "domain-name",
    "domain|ip": "domain-name",
    "url": "url",
    "uri": "url",
    "email": "email-addr",
    "email-src": "email-addr",
    "email-dst": "email-addr",
    "email-reply-to": "email-addr",
    "md5": "file.MD5",
    "filename|md5": "file.MD5",
    "sha1": "file.SHA-1",
    "filename|sha1": "file.SHA-1",
    "sha256": "file.SHA-256",
    "filename|sha256": "file.SHA-256",
    "filename": "file",
    "mutex": "mutex",
    "regkey": "windows-registry-key",
    "mac-address": "mac-addr",
    "AS": "autonomous-system",
}


def sanitize(tag):
    """A comma separates tags, so a tag cannot contain one.

    `sanitize_tag` in src/ingest/misp.rs, which replaces it with a semicolon
    rather than dropping the tag — a MISP galaxy tag often contains a comma
    inside its quoted value.
    """
    return tag.strip().replace(",", ";")


def fetch(path):
    with urllib.request.urlopen(f"{FEED}/{path}", timeout=60) as response:
        return json.load(response)


def attributes_of(event):
    """Every attribute, including the ones hanging off objects.

    MISP puts related attributes inside objects — a file with its hashes, a
    network connection with its endpoints — and `collect` in the ingest walks
    into them, so this does too.
    """
    found = list(event.get("Attribute", []))
    for obj in event.get("Object", []):
        found.extend(obj.get("Attribute", []))
    return found


def items_from(event):
    event_tags = [
        sanitize(tag["name"])
        for tag in event.get("Tag", [])
        if tag.get("name")
    ]
    items = []
    seen = set()

    for attribute in attributes_of(event):
        misp_type = attribute.get("type")
        value = attribute.get("value") or attribute.get("value1")
        namespace = NAMESPACES.get(misp_type)
        if not (misp_type and value and namespace):
            continue

        # The same value can appear twice in one event — once loose and once in
        # an object. Two sightings of one published fact would overstate how
        # often it was seen, which is the one number this database is for.
        if (namespace, value) in seen:
            continue
        seen.add((namespace, value))

        tags = [f"misp-type:{misp_type}"]
        if misp_type in STIX_TYPES:
            tags.append(f"stix-type:{STIX_TYPES[misp_type]}")
        if attribute.get("category"):
            tags.append(f"misp-category:{sanitize(attribute['category'])}")
        if event.get("uuid"):
            tags.append(f"misp-event:{event['uuid']}")
        if (attribute.get("comment") or "").strip():
            tags.append(f"description:{sanitize(attribute['comment'])}")
        for tag in attribute.get("Tag", []):
            if tag.get("name"):
                tags.append(sanitize(tag["name"]))
        tags.extend(event_tags)

        item = {
            "namespace": namespace,
            "value": value,
            # Preserved so the histogram on the value page is the feed's own
            # chronology rather than the moment the demo was started.
            "timestamp": int(attribute["timestamp"]),
            "tags": ",".join(dict.fromkeys(tags)),
        }
        items.append(item)

    return items


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uuid", default=DEFAULT_EVENT)
    parser.add_argument("--list", action="store_true", help="list recent events")
    parser.add_argument("--out", default="doc/docker/demo-data.json")
    parser.add_argument(
        "--force",
        action="store_true",
        help="convert an event that is not CIRCL-published and marked for "
        "unrestricted sharing. Do not commit the result.",
    )
    args = parser.parse_args()

    if args.list:
        manifest = fetch("manifest.json")
        rows = sorted(
            ((v.get("date", ""), k, v.get("info", "")) for k, v in manifest.items()),
            reverse=True,
        )
        for date, uuid, info in rows[:40]:
            print(f"{date}  {uuid}  {info[:70]}")
        return 0

    event = fetch(f"{args.uuid}.json")["Event"]

    tags = {tag.get("name", "").lower() for tag in event.get("Tag", [])}
    org = event.get("Orgc", {}).get("name", "")
    public = tags & PUBLIC_TLP
    if not args.force:
        if not public:
            marking = ", ".join(sorted(t for t in tags if t.startswith("tlp:")))
            print(
                f"{args.uuid} is marked {marking or 'with no TLP at all'}, so it is not "
                f"for unrestricted sharing and will not be converted.\n"
                f"Pick another event, or pass --force if you know what you are doing "
                f"and are not committing the result.",
                file=sys.stderr,
            )
            return 2
        if org != PREFERRED_ORG:
            print(
                f"{args.uuid} was published by {org!r} rather than {PREFERRED_ORG}. It is "
                f"marked for unrestricted sharing, but keeping the provenance of committed "
                f"data to one organisation is easier to stand behind.\n"
                f"Pass --force to use it anyway.",
                file=sys.stderr,
            )
            return 2

    items = items_from(event)
    if not items:
        print(f"{args.uuid} has no attributes this maps; try another", file=sys.stderr)
        return 1

    payload = {
        "_source": {
            "feed": FEED,
            "event": args.uuid,
            "info": event.get("info"),
            "event_date": event.get("date"),
            "published_by": org,
            "marking": sorted(public) or sorted(t for t in tags if t.startswith("tlp:")),
            "retrieved": datetime.date.today().isoformat(),
            "generated_by": "doc/docker/fetch-demo-data.py",
            "credit": f"\u00a9 {org}. Sample data from the CIRCL MISP OSINT feed, {FEED}",
            "terms": (
                "Marked TLP:CLEAR, which says it may be shared without restriction "
                "but is a handling designation rather than a copyright licence: the "
                "feed states no licence and CIRCL reserves copyright. Kept here as a "
                "small attributed sample so the demo has real data in it. If that is "
                "not a basis you are comfortable with, run fetch-demo-data.py "
                "yourself instead of committing its output."
            ),
            "note": (
                "Indicators someone else published, and a dated snapshot: the feed "
                "is rewritten daily and this is not current. Read as data, not as "
                "advice."
            ),
        },
        "items": items,
    }

    with open(args.out, "w") as out:
        json.dump(payload, out, indent=1, sort_keys=False)
        out.write("\n")

    # A couple of values for seed.sh to point at, so it can show a repeat count
    # and a value seen in two namespaces without hardcoding indicators that
    # change whenever this is re-run against another event.
    picks = args.out.rsplit(".", 1)[0] + ".env"
    repeat = next((i for i in items if i["namespace"] == "misp/ips"), items[0])
    other = next(
        (i for i in items if i["value"] != repeat["value"]
         and i["namespace"] == repeat["namespace"]),
        repeat,
    )
    with open(picks, "w") as out:
        out.write(
            "# Written by fetch-demo-data.py, read by seed.sh. Two values from\n"
            "# demo-data.json, so the script can demonstrate a repeat sighting\n"
            "# and consensus across namespaces without naming indicators that\n"
            "# change when the data is refreshed.\n"
        )
        out.write(f'REPEAT_NAMESPACE="{repeat["namespace"]}"\n')
        out.write(f'REPEAT_VALUE="{repeat["value"]}"\n')
        out.write(f'RETAG_VALUE="{other["value"]}"\n')
    print(f"{picks}: repeat={repeat['value']} retag={other['value']}")

    namespaces = {}
    for item in items:
        namespaces[item["namespace"]] = namespaces.get(item["namespace"], 0) + 1
    print(f"{args.out}: {len(items)} items from \"{event.get('info', '')[:50]}\"")
    for namespace, count in sorted(namespaces.items()):
        print(f"  {namespace:22} {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
