# The management interface

`https://your-server:9999/_management`, with a key holding `admin`. On a fresh
install that is `changeme`, and changing it is the first thing to do.

It is one page — markup and script in a single file compiled into the binary —
so there is nothing to deploy and nothing to keep in step with the server.

## Browsing

![A namespace is a path, so it browses like folders.](images/ui-browse.png){width=100%}

**folder** means other namespaces sit underneath it, **namespace** means it
holds values of its own, and a path can be both. The storage column is from
chapter 4: `hot` stays in memory, `warm` is written out after the seconds
beside it, `cold` goes at the next sweep. Those settings belong to the whole
top-level namespace, because that is one file paged in and out as a unit —
which the page says out loud when you change one.

## Values

![The values in a namespace, with what the export will make of them.](images/ui-values.png){width=100%}

The **Observable** column is what the STIX export will call each value, sitting
next to the tags that decide it — on purpose, because the column that tells you
a value has no observable type is next to the one you fix it in.

Tags are editable in place, and the box completes what you type from tags
already in use.

## One value

![One value: its history, its tags, and where else it has been seen.](images/ui-value.png){width=100%}

The histogram is the hourly statistics from `/rs`. **Consensus** is how many
namespaces have seen this value at all, and the list below says which — the
answer to "is this just my proxy, or is it in three feeds as well?".

## Tags

![The vocabulary: colours, what each tag means, and what is in use.](images/ui-tags.png){width=100%}

Chapter 6 is this page in full.

## Galaxy

![The galaxy, and the peers under it.](images/ui-galaxy.png){width=100%}

The graph is drawn from one request that walks the whole cascade. Below it, the
peers table is where a node is added, re-keyed, disabled or removed — chapter
9.

Note what `Last answered` means: when this server last got a health reply from
that peer. It is about the server, not about any value.

## Activity

How busy each top-level namespace has been: every read and every accepted
write, counted against the first segment of the namespace, so `feeds/misp/ips`
counts towards `feeds`. It answers the questions the data itself cannot —
is anyone still querying this feed, did the ingest stop on Tuesday, which
customer is doing all the reading.

![Ninety days, one row per namespace. The honeypot's scanning campaign and the customer that arrived six weeks ago are both visible without reading a number.](images/ui-activity.png){width=100%}

Each namespace is a row of cells, one per day or per hour, the way a status
page draws uptime: **reads** in blue, **writes** in orange, darker for more.
The shades are on one scale across every namespace on the page, so two cells
of the same shade saw about the same traffic, whichever row they are in. A
grey cell is a bucket in which nothing happened at all.

Beside each name are the totals for the window and how they compare with the
window of the same length just before it — ▲ 17% against the previous ninety
days, here. When that earlier window reaches back past what is kept, the
comparison is left out rather than computed against half a window.

**Browsing.** The window is 24 or 48 hours, a week by the hour, or 30 days, 90
days or a year by the day. **Earlier** and **Later** move a whole window at a
time, so nothing is shown twice; **Now** comes back. Hovering a cell gives its
exact counts. **Clicking a day opens its 24 hours**, which is the way into a
spike:

![The day before, by the hour. Working hours show on every namespace but the honeypot, which is written to around the clock.](images/ui-activity-hours.png){width=100%}

A year is drawn as a calendar instead, one column per week and one row per
weekday, because 365 slivers in a row are unreadable. Gaps and weekly rhythms
are what it is for:

![A year of one namespace. Twenty days when the feed delivered nothing, and nobody read it either.](images/ui-activity-year.png){width=100%}

**Comparing.** Tick namespaces to draw them on one chart below — the busiest
three are ticked to begin with, and up to eight can be. It shows reads or
writes, never both: they differ by orders of magnitude and would not share an
axis.

![Three namespaces' reads on one chart.](images/ui-activity-compare.png){width=100%}

What is counted is what clients asked for. Every route counts — `/r`, `/rb`,
`/w`, `/wb`, DNS, the ZMQ ingest, and values added from this interface. A read
of a value that is not there still counts; a write that was refused does not.
The database's own bookkeeping — `_all`, `_shadow/*`, `_config/*` — is not
counted, and neither are galaxy merges: a value one node forwards to another
was a write on the first node, not a second write on the second.

Hours are kept for 31 days and days for 400, all in UTC. The counts are saved
with snapshots as `activity.json` in `dbdir`, so they survive a restart. A
namespace's row is shown only to a key that can read all of it: a total for
`feeds` says something about everything under it.

Counting costs a brief lock on every read and write. If that matters more than
the picture, `activity = false` in `[daemon]` turns it into a single flag
check; the page then says counting is off, and still shows whatever was counted
before.

## Keys

![What each key may reach.](images/ui-keys.png){width=100%}

Create, scope and revoke. The guard rails refuse any change that would leave no
admin key at all, by demotion or by deletion — there is no way to lock yourself
out from this page.

**Keys are per server.** This page shows the ACL of the server you are
connected to; the keys a node accepts live on that node. See chapter 9 for the
two mechanisms that connect them.

## Configuration

Read-only, and says so: it is what the server read at startup. Everything on it
comes from `sightingdb.toml`, which this program does not rewrite.

The exceptions are the four machine-owned files from chapter 4 — keys, tiers,
tag colours and peers — each edited on its own page.

It also shows the TLS certificate's expiry, and says **about to expire** when
there are fewer than 30 days left. A certificate that quietly lapses takes a
galaxy with it, since peers stop being able to authenticate to each other.

## Exporting

**Export STIX** on a namespace asks two things before it runs: whether to
include the subnamespaces beneath it, and what to do with values whose
observable type could not be worked out — leave them out, or export them
flagged as untyped. Chapter 11.

## Rejections

Every write path records what it turned away, newest first, including the ZMQ
ingest which has no caller of its own to tell. It is the answer to "the feed
says it sent fifty thousand and I have forty-nine".

It is bounded and in memory: a record kept to make something visible, not a
fact about the data.

## A note on caching

The page is served with `Cache-Control: no-cache`, so a browser revalidates it
every time. It is the whole application in one file, and a cached copy means a
browser running the previous version's JavaScript against this version's API —
which looks like the server being wrong rather than the page being old.

If you ever see an interface that disagrees with the API, reload it once.
