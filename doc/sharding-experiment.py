#!/usr/bin/env python3
"""Measurements behind the placement decisions in storage-future.txt.

Two questions, both answered by running this:

  1. How evenly does a placement function spread real sighting values?
  2. How much data moves when a node is added?

Nothing here touches SightingDB. It is a few hundred lines of arithmetic over
synthetic-but-shaped values, kept in the repository so the numbers in the
design document can be re-checked rather than taken on trust.

    python3 doc/sharding-experiment.py

The values are deliberately *not* uniform random strings. Threat intelligence
is clustered — a handful of /8s carry most of the addresses, a handful of
hostnames prefix most of the domains, and every URL begins with the same seven
characters. A placement function that looks fine on random input can fall over
on this.
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

    # Every URL begins "http://". This is what breaks a prefix-based function.
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


def first_four_xor(value, nodes):
    """The first four bytes, XOR-folded. The original proposal."""
    head = value.encode()[:4].ljust(4, b"\0")
    return (head[0] ^ head[1] ^ head[2] ^ head[3]) % nodes


def first_four_word(value, nodes):
    """The first four bytes read as one integer: the kinder reading of it."""
    head = value.encode()[:4].ljust(4, b"\0")
    return int.from_bytes(head, "big") % nodes


def whole_value(value, nodes):
    """A hash of the whole value."""
    return fnv1a(value) % nodes


def rendezvous(value, node_names, hashf=sha256_64):
    """Highest-random-weight: the node whose (value, node) hash is largest.

    No ring, no virtual nodes, no state beyond the member list, and adding a
    node moves only the keys that node wins — which is the minimum possible.
    """
    return max(node_names, key=lambda name: hashf(f"{value}:{name}"))


# ---------------------------------------------------------------------------
# Question 1: distribution
# ---------------------------------------------------------------------------


def distribution(values):
    print("Distribution")
    print("============")
    print(f"{len(values)} values shaped like a real feed.\n")

    for nodes in NODE_COUNTS:
        ideal = 100 / nodes
        print(f"-- {nodes} nodes, ideal share {ideal:.1f}% each")
        candidates = [
            ("XOR of first 4 bytes", first_four_xor),
            ("first 4 bytes as a word", first_four_word),
            ("hash of whole value", whole_value),
        ]
        for name, place in candidates:
            counts = collections.Counter(place(v, nodes) for v in values)
            shares = [100 * counts.get(i, 0) / len(values) for i in range(nodes)]
            worst = max(shares)
            print(
                f"   {name:26} min {min(shares):5.1f}%  max {worst:5.1f}%"
                f"   imbalance {worst / ideal:.2f}x"
            )
        print()


# ---------------------------------------------------------------------------
# Question 2: what moves when a node joins
# ---------------------------------------------------------------------------


def rebalancing(values):
    print("Rebalancing")
    print("===========")
    print("Share of all values that change node when one is added.\n")

    print(f"   {'change':<10} {'mod-n':>9} {'HRW+FNV':>9} {'HRW+SHA':>9} {'minimum':>9}")
    for old, new in [(3, 4), (4, 5), (8, 9), (8, 16)]:
        before = [f"n{i}" for i in range(old)]
        after = [f"n{i}" for i in range(new)]

        moved_mod = sum(1 for v in values if whole_value(v, old) != whole_value(v, new))
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
    print("   mod-n moves most of the keyspace, because changing the divisor")
    print("   renumbers nearly everything. Doubling is its one lucky case:")
    print("   hash % 8 and hash % 16 agree whenever the fourth bit is clear,")
    print("   so exactly half stay put. Growing by one node is the bad case,")
    print("   and growing by one node is what actually happens.")
    print()
    print("   HRW+FNV is the trap: FNV-1a spreads values perfectly well (see")
    print("   above) but makes a poor rendezvous weight, because appending")
    print("   ':n0' / ':n1' perturbs it in a structured way and the comparison")
    print("   between nodes becomes correlated. It only reaches the minimum by")
    print("   luck, at 3 -> 4. Rendezvous needs real avalanche in the hash.")


if __name__ == "__main__":
    values = corpus()
    distribution(values)
    rebalancing(values)
