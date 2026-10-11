# Tags

A sighting on its own is *namespace, value, count, first seen, last seen*. That
answers "how often, and when" and nothing else — it does not say what the value
**is**, who saw it, or how it may be shared. Tags carry that.

## The shape of a tag set

A comma-separated set, each entry either a bare label or `key:value`:

```text
stix-type:ipv4-addr, tlp:amber, confidence:80, identity:Beta Cyber Intelligence
```

Comma is the separator because the interesting values contain spaces — an
identity, a description — so a tag may contain **anything except a comma**,
colons included. That is what a URL and an RFC 3339 timestamp need. Whitespace
around entries is trimmed, and a key may repeat.

## They merge

```bash
curl -H 'Authorization: changeme' \
  'http://localhost:9999/w/feeds/ips?val=198.51.100.23&tags=stix-type:ipv4-addr'
curl -H 'Authorization: changeme' \
  'http://localhost:9999/w/feeds/ips?val=198.51.100.23&tags=tlp:amber'
```

The value now carries both. Two feeds that each know something different about
an address both contribute, and neither erases the other.

Which means **a write can never take a tag off**. That is the management
interface's job:

```bash
curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
  -X POST http://localhost:9999/_management/api/tags \
  -d '{"namespace":"feeds/ips","value":"198.51.100.23","tags":"tlp:green"}'
```

That replaces the set outright. It is not a sighting: nothing is counted and no
timestamp moves.

> In a galaxy the replacement is pushed to every mirror as it is made, and the
> answer says which took it. A tag change is not a sighting, so nothing else
> would ever carry it. Chapter 9.

## The vocabulary the export reads

Anything you like is kept, and these are the keys the STIX export understands:

| Tag | What it does |
| --- | --- |
| `stix-type:<type>` | The observable type, and so the pattern: `ipv4-addr`, `domain-name`, `url`, `email-addr`, `mutex`, `windows-registry-key`, or `file.<ALGORITHM>` for a hash. |
| `stix-id:indicator--<uuid>` | Reuse this indicator id rather than minting one. |
| `indicator-type:<value>` | Adds to `indicator_types`. Repeatable. |
| `tlp:<label>` | Marks the indicator and the sighting with the TLP marking. |
| `confidence:<0-100>` | STIX `confidence` on both objects. |
| `identity:<name>` | Who saw it. Becomes an `identity` object. Repeatable. |
| `name:`, `description:` | Indicator name and description. |
| `valid-until:` | Indicator `valid_until`, as RFC 3339 or Unix seconds. |

The MISP importer also writes `misp-type:`, `misp-category:`, `misp-event:`
and MISP's own tags as they were published.

## Colours, and what a tag means

The **Tags** page gives every tag a colour and a description, and that is what
makes a marking readable at a glance instead of being grey text among twenty
others.

![The tag vocabulary. Families, usage counts, and tags seen but not defined.](images/ui-tags.png){width=100%}

It decides **presentation only**. A value can carry a tag nothing here defines
and that is not an error — a feed brings what it brings, and refusing tags to
keep a table tidy would lose data.

### Families

A name ending in `:` is a family and colours everything beneath it:

```text
stix-type:          colours stix-type:ipv4-addr, stix-type:domain-name, ...
misp-galaxy:        colours every MISP galaxy tag
```

Half the vocabulary above is `key:value` with an open set of values, which
could not be enumerated even in principle. An exact entry beats its family, and
the longest family wins. It is also the shape of a MISP machine tag —
`namespace:predicate` — so a whole MISP taxonomy can be coloured by its
namespace.

### What ships

A new installation starts with the five TLP 2.0 labels — `tlp:clear`,
`tlp:green`, `tlp:amber`, `tlp:amber+strict`, `tlp:red` — plus `tlp:white`,
which 2.0 renamed to CLEAR, because sources still send it. CIRCL's public OSINT
feed tags its events `tlp:white` *and* `tlp:clear`, so a real import carries
both; WHITE is given CLEAR's colour, because that is what it means. A colour
per family of SightingDB's own vocabulary comes with them.

The colours are MISP's own, from its `tlp` taxonomy, which follows FIRST's, so
a tag exported to MISP and back looks the same in both.

Seeded, not insisted upon. Once there is a `tags_file` the table is yours: any
of them can be recoloured or removed, and nothing puts them back.

```bash
curl -H 'Authorization: changeme' -H 'Content-Type: application/json' \
  -X POST http://localhost:9999/_management/api/tags/vocabulary \
  -d '{"name":"needs-review","colour":"#AA33CC","description":"Ours, not from a feed."}'
```

```bash
curl -H 'Authorization: changeme' -X DELETE \
  'http://localhost:9999/_management/api/tags/vocabulary?tag=needs-review'
```

Removing a colour **does not remove the tag from the values**. This is a
presentation setting, and deleting data from a colour picker would be a trap —
so the tag stays in the table, listed as undefined, for as long as anything
carries it.

Changing the table needs an `admin` key, or one with read *and* write across
all namespaces. A key that can already write any tag onto any value is not
meaningfully restrained by being unable to say what colour it is shown in — but
a key scoped to a subtree cannot, since the vocabulary is server-wide and
changing it would reach past that scope.

### Tags found on values

The page lists tags nothing has defined, so adopting one is a click rather than
a discovery. Those are **grouped where a key is being used as a free-text
field**: MISP turns an attribute's comment into `description:<text>`, and real
comments are paragraphs — a single imported CIRCL event produced seven rows of
prose. A key with more than three distinct values is shown once, as its family,
saying how many it stands for. Three or fewer keep their own rows, because that
is a vocabulary rather than a free-text field, and giving every `tlp:` label one
colour would defeat the point of a marking.

### Typing one

The tag box completes what you are typing, offering tags already in use. It
completes the entry after the last comma rather than the whole field, because
the point is to type a tag the same way twice. A family is offered with its
colon kept, leaving the cursor ready for the value.

## Where tags show up

In `/r` and `/rs` responses, in the DNS TXT answer, in the STIX export, and
everywhere a value appears in the interface.

![A value, its history and its tags.](images/ui-value.png){width=100%}
