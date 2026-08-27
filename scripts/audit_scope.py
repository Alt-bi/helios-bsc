#!/usr/bin/env python3
"""Measure the audit scope: the trust surface, tests excluded.

The scope is the code where a defect yields a *wrong verified answer* rather than a
crash or a refusal. That is a judgement call about which files belong, so the file list
below is explicit rather than inferred. What the script removes mechanically is the part
nobody would pay a reviewer to read: `#[cfg(test)]` blocks, and files under a `tests/`
directory.

The figure this prints gets quoted outside this repository, where nobody can check it
against the code. So it has to be reproducible by anyone who doubts it:

    python scripts/audit_scope.py

`--check N` exits non-zero once the total has drifted more than `--tolerance` percent
away from N, so CI notices when the code and the quoted figure part company. The band is
there on purpose: a tripwire that fires on a hundred lines of ordinary growth gets muted,
and a muted check is worse than none.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (label, [paths], why it is in scope) -- paths are files or directories.
SCOPE: list[tuple[str, list[str], str]] = [
    (
        "crates/helios-bsc-consensus",
        ["crates/helios-bsc-consensus/src"],
        "ECDSA seals, epoch transitions, BEP-126 BLS attestation",
    ),
    (
        "crates/helios-bsc-execution",
        ["crates/helios-bsc-execution/src"],
        "Merkle-Patricia proofs, RLP, revm, envelope parsing",
    ),
    (
        "bin/helios-bsc/src/rpc_server*",
        ["bin/helios-bsc/src/rpc_server.rs", "bin/helios-bsc/src/rpc_server"],
        "Method policy, receipt and log derivation, every fail-closed boundary",
    ),
    (
        "bin/helios-bsc/src/sync.rs, upstream.rs",
        ["bin/helios-bsc/src/sync.rs", "bin/helios-bsc/src/upstream.rs"],
        "Header-walk state machine, parsing bytes chosen by someone else",
    ),
    (
        "bin/helios-bsc/src/main.rs",
        ["bin/helios-bsc/src/main.rs"],
        "The checkpoint bootstrap -- the trust root every later proof is checked against",
    ),
    (
        "crates/helios-bsc-config",
        ["crates/helios-bsc-config/src"],
        "Chain params and the fork schedule that decides which rules are applied",
    ),
    (
        "crates/helios-bsc-types",
        ["crates/helios-bsc-types/src"],
        "Hex and quantity decoding of attacker-chosen bytes",
    ),
    (
        "crates/helios-bsc-rpc",
        ["crates/helios-bsc-rpc/src"],
        "The transport every untrusted byte arrives over",
    ),
]

# Deliberately out of scope, and why -- a defect here yields a wrong *diagnostic* or a
# crash, not a wrong verified answer:
#   bin/helios-bsc/src/diff.rs         oracle comparison for the soak
#   bin/helios-bsc/src/health.rs       liveness probe
#   bin/helios-bsc/src/bind.rs         listen-address parsing
#   bin/helios-bsc/src/soak_state.rs   soak checkpointing across restarts
#   bin/helios-bsc/src/adversarial.rs  test harness
#   crates/helios-bsc-mock             test harness

CFG_TEST = re.compile(r"^\s*#\[cfg\(test\)\]\s*$")


def strip_test_blocks(text: str) -> list[str]:
    """Drop every `#[cfg(test)]` item, by counting braces from its opening line.

    Braces inside string and char literals and inside comments would throw the count
    off, so those are blanked before counting. This is a line counter, not a parser --
    it only has to be right about brace depth.
    """
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()  # a file that ends in a newline is not one line longer
    out: list[str] = []
    i = 0
    while i < len(lines):
        if not CFG_TEST.match(lines[i]):
            out.append(lines[i])
            i += 1
            continue

        # Skip the attribute, then the item it applies to.
        i += 1
        depth = 0
        opened = False
        while i < len(lines):
            code = blank_noncode(lines[i])
            depth += code.count("{") - code.count("}")
            if "{" in code:
                opened = True
            i += 1
            if opened and depth <= 0:
                break
            # An attribute on a `use` or a one-line item: no braces at all.
            if not opened and code.rstrip().endswith(";"):
                break
    return out


def blank_noncode(line: str) -> str:
    """Replace string/char literals and line comments with spaces."""
    out = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c == "/" and i + 1 < n and line[i + 1] == "/":
            break
        if c == '"':
            i += 1
            while i < n:
                if line[i] == "\\":
                    i += 2
                    continue
                if line[i] == '"':
                    i += 1
                    break
                i += 1
            out.append(" ")
            continue
        if c == "'":
            # Could be a lifetime (`'a`) -- only treat it as a char literal when it
            # closes on this line within a few characters.
            close = line.find("'", i + 1)
            if 0 < close <= i + 4:
                i = close + 1
                out.append(" ")
                continue
        out.append(c)
        i += 1
    return "".join(out)


def rust_files(rel: str) -> list[Path]:
    p = ROOT / rel
    if p.is_file():
        return [p]
    if not p.is_dir():
        raise SystemExit(f"scope path does not exist: {rel}")
    return sorted(
        f
        for f in p.rglob("*.rs")
        if "tests" not in f.relative_to(p).parts and f.name != "tests.rs"
    )


def count(rel: str) -> int:
    total = 0
    for f in rust_files(rel):
        text = f.read_text(encoding="utf-8").replace("\r\n", "\n")
        total += len(strip_test_blocks(text))
    return total


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", type=int, help="the figure the documents quote")
    ap.add_argument(
        "--tolerance",
        type=float,
        default=5.0,
        help="percent the total may drift from --check before this fails (default 5)",
    )
    args = ap.parse_args()

    rows = []
    grand = 0
    for label, paths, why in SCOPE:
        n = sum(count(p) for p in paths)
        grand += n
        rows.append((label, n, why))

    width = max(len(r[0]) for r in rows)
    print(f"| {'Area':<{width}} | Lines | Why it is in scope |")
    print(f"|{'-' * (width + 2)}|------:|---|")
    for label, n, why in rows:
        print(f"| `{label}`{' ' * (width - len(label))} | {n:,} | {why} |")
    rounded = round(grand / 100) * 100
    print(f"| **Total** {' ' * (width - 7)} | **~{rounded:,}** | |")
    print(f"\nexact: {grand:,} lines, tests excluded")

    if args.check is not None:
        drift = abs(grand - args.check) / args.check * 100
        if drift > args.tolerance:
            print(
                f"\nFAIL: the quoted figure is ~{args.check:,} lines, the code now has "
                f"{grand:,} ({drift:.1f}% away, band is {args.tolerance}%).\n"
                f"Update whatever quotes it, and the --check value in "
                f".github/workflows/ci.yml together.",
                file=sys.stderr,
            )
            return 1
        print(f"within {args.tolerance}% of the quoted ~{args.check:,} ({drift:.1f}% away)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
