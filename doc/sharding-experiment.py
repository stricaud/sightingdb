#!/usr/bin/env python3
"""Measurements behind the read-routing decisions in storage-future.txt.

SightingDB divides work by *namespace*, not by value: a namespace is already
the storage unit, so mirroring whole namespaces keeps listing, counting,
deleting and exporting them local. Nothing here decides where data lives.

What this measures is the smaller question that remains. When several mirrors
hold the same namespace, a read has to pick one of them — and pick the *same*
one for a given value every time, or two consecutive reads served by different
mirrors can show a count going down while async sync catches up.

Two things about that choice:

  1. How much read traffic repoints when the mirror set changes?
  2. Does the choice of hash matter?

It matters more than it looks: a hash that spreads values perfectly well can
still make a poor rendezvous weight. That result is the reason this file is in
the repository rather than being a sentence in the design document.

    python3 doc/sharding-experiment.py

The values are deliberately *not* uniform random strings. Threat intelligence
is clustered — a handful of /8s carry most of the addresses, a handful of
hostnames prefix most of the domains, and every URL begins with the same seven
characters.
"""

import collections
import hashlib
import random

NODE_COUNTS = (4, 8)
SAMPLE = 20_000
SEED = 7


# ---------------------------------------------------------------------------
# The corpus
# ---------------------------------------------------------------------------


def corpus(n=SAMPLE):
    """Values shaped like the ones a feed actually carries."""
    random.seed(SEED)
    out = []
    quarter = n // 4

    # Addresses cluster in a few ranges, as real feeds do.
    for _ in range(quarter):
        first = random.choice([192, 10, 172, 185, 45, 91, 104])
        out.append(
            f"{first}.{random.randint(0, 255)}."
            f"{random.randint(0, 255)}.{random.randint(1, 254)}"
        )

    # Domains share a small set of leading labels.
    for _ in range(quarter):
        host = random.choice(["www", "mail", "cdn", "api", "ns1", ""])
        label = "".join(random.choice("abcdefghijklmnop") for _ in range(random.randint(5, 11)))
        out.append(f"{host + '.' if host else ''}{label}.com")

    # Every URL begins "http://", which is what punishes any function that
    # looks at a value's first few bytes instead of all of it.
    for _ in range(quarter):
        label = "".join(random.choice("abcdefghijklmnop") for _ in range(10))
        out.append(f"http://{label}.example/path")

    # Hashes are the one genuinely uniform case.
    for _ in range(quarter):
        out.append("".join(random.choice("0123456789abcdef") for _ in range(64)))

    return out


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------


def fnv1a(text):
    """FNV-1a, 64 bit. Fast, and good enough to spread values evenly."""
    h = 0xCBF29CE484222325
    for byte in text.encode():
        h ^= byte
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def sha256_64(text):
    """The top 64 bits of SHA-256. Slower, and with the avalanche rendezvous
    weighting needs — see `rebalancing` below for what happens without it."""
    return int.from_bytes(hashlib.sha256(text.encode()).digest()[:8], "big")


# ---------------------------------------------------------------------------
# Placement functions
# ---------------------------------------------------------------------------


def modulo(value, mirrors):
    """Pick a mirror by hash modulo the mirror count.

    The obvious approach, and the one to avoid: changing the count renumbers
    nearly everything. Here to show by how much.
    """
    return fnv1a(value) % mirrors


def rendezvous(value, mirrors, hashf=sha256_64):
    """Highest-random-weight: the mirror whose (value, mirror) hash is largest.

    No ring, no virtual nodes, no state beyond the mirror list, and adding a
    mirror repoints only the values it wins — the minimum possible. Every
    server computes it independently from the same list, which is why a galaxy
    that disagrees about membership disagrees about routing.
    """
    return max(mirrors, key=lambda name: hashf(f"{value}:{name}"))


# ---------------------------------------------------------------------------
# Question 1: is read load spread evenly across the mirrors?
# ---------------------------------------------------------------------------


def spread(values):
    print("Read spread across mirrors")
    print("==========================")
    print(f"{len(values)} values shaped like a real feed.\n")

    for mirrors in NODE_COUNTS:
        ideal = 100 / mirrors
        names = [f"m{i}" for i in range(mirrors)]
        counts = collections.Counter(rendezvous(v, names) for v in values)
        shares = [100 * counts.get(n, 0) / len(values) for n in names]
        print(
            f"   {mirrors} mirrors, ideal {ideal:.1f}% each:"
            f"  min {min(shares):5.1f}%  max {max(shares):5.1f}%"
            f"   imbalance {max(shares) / ideal:.2f}x"
        )
    print()


# ---------------------------------------------------------------------------
# Question 2: what repoints when the mirror set changes
# ---------------------------------------------------------------------------


def rebalancing(values):
    print("Repointing")
    print("==========")
    print("Share of values whose chosen mirror changes when one is added.")
    print("No data moves: this is read routing only.\n")

    print(f"   {'change':<10} {'mod-n':>9} {'HRW+FNV':>9} {'HRW+SHA':>9} {'minimum':>9}")
    for old, new in [(3, 4), (4, 5), (8, 9), (8, 16)]:
        before = [f"n{i}" for i in range(old)]
        after = [f"n{i}" for i in range(new)]

        moved_mod = sum(1 for v in values if modulo(v, old) != modulo(v, new))
        moved_fnv = sum(
            1 for v in values if rendezvous(v, before, fnv1a) != rendezvous(v, after, fnv1a)
        )
        moved_sha = sum(
            1 for v in values if rendezvous(v, before, sha256_64) != rendezvous(v, after, sha256_64)
        )

        n = len(values)
        print(
            f"   {f'{old} -> {new}':<10}"
            f" {100 * moved_mod / n:8.1f}%"
            f" {100 * moved_fnv / n:8.1f}%"
            f" {100 * moved_sha / n:8.1f}%"
            f" {100 * (new - old) / new:8.1f}%"
        )

    print()
    print("   mod-n repoints most of the values, because changing the divisor")
    print("   renumbers nearly everything. Doubling is its one lucky case:")
    print("   hash % 8 and hash % 16 agree whenever the fourth bit is clear,")
    print("   so exactly half stay put. Gaining one mirror is the bad case,")
    print("   and gaining one mirror is what actually happens.")
    print()
    print("   HRW+FNV is the trap: FNV-1a spreads values perfectly well (see")
    print("   above) but makes a poor rendezvous weight, because appending")
    print("   ':n0' / ':n1' perturbs it in a structured way and the comparison")
    print("   between nodes becomes correlated. It only reaches the minimum by")
    print("   luck, at 3 -> 4. Rendezvous needs real avalanche in the hash.")
    print()
    print("   Placement must also be STABLE across releases, so never reach")
    print("   for std's DefaultHasher here: it is explicitly not stable, and a")
    print("   toolchain upgrade would silently repoint every read.")


if __name__ == "__main__":
    values = corpus()
    spread(values)
    rebalancing(values)
