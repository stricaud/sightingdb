"""Fail when an advisory ignored in `.cargo/audit.toml` no longer applies.

`cargo audit` says nothing at all about an advisory it has been told to ignore,
so an exception added for a dependency that cannot yet be upgraded quietly
outlives its reason: the upgrade lands, the entry stays, and the next advisory
against the same crate is silently swallowed too.

This re-runs the audit *without* the configuration — from another directory,
since that is where `cargo audit` reads it from — and checks the two lists
agree. An ignored advisory that no longer fires is an entry to delete.

Run with: python3 .github/check-audit-ignores.py
"""
import json, pathlib, subprocess, sys, tempfile, tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = ROOT / ".cargo" / "audit.toml"


def ignored() -> set[str]:
    if not CONFIG.exists():
        return set()
    with CONFIG.open("rb") as handle:
        return set(tomllib.load(handle).get("advisories", {}).get("ignore", []))


def reported() -> set[str]:
    """Advisory ids `cargo audit` finds when nothing is ignored."""
    with tempfile.TemporaryDirectory() as elsewhere:
        result = subprocess.run(
            ["cargo", "audit", "--json", "--no-fetch",
             "--file", str(ROOT / "Cargo.lock")],
            cwd=elsewhere, capture_output=True, text=True,
        )
    # A vulnerability found is a non-zero exit and expected here; only a failure
    # to produce a report at all is a problem.
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("cargo audit produced no report:", result.stderr.strip(), file=sys.stderr)
        sys.exit(2)
    return {item["advisory"]["id"] for item in report["vulnerabilities"]["list"]}


def main() -> int:
    exceptions, found = ignored(), reported()
    if not exceptions:
        print("No audit exceptions.")
        return 0

    for advisory in sorted(exceptions):
        print(f"ignored: {advisory}", "(still applies)" if advisory in found else "")

    stale = exceptions - found
    if stale:
        print(
            "\nThese no longer apply and should be removed from .cargo/audit.toml:\n  "
            + "\n  ".join(sorted(stale)),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
