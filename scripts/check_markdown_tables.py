#!/usr/bin/env python3
"""Refuse a markdown table row that is not in a table.

STATUS.md's milestone table had two stray blank lines in it. GitHub renders a `| a | b |`
line that follows a blank line as literal text, not as a table row -- so the four newest
milestones, including the container image and both guards added that day, showed up as
pipe-soup on the page every reader lands on first. `cargo test` cannot see that, no link
checker sees it, and nobody reading the diff of a one-row addition sees it either.

The rule: a line starting with `|` must be preceded either by another `|` line or by
nothing (it opens the table, and the line after it must be the header delimiter).
"""
import argparse
import io
import os
import re
import sys

DELIM = re.compile(r"^\|[\s:|-]+\|\s*$")


def check(path: str) -> list[str]:
    lines = io.open(path, encoding="utf-8").read().replace("\r\n", "\n").split("\n")
    bad = []
    fenced = False
    for i, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            fenced = not fenced
        if fenced or not line.startswith("|"):
            continue
        prev = lines[i - 1] if i else ""
        if prev.startswith("|"):
            continue
        # Opening a table: the next line has to be the header delimiter.
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if DELIM.match(nxt):
            continue
        bad.append(f"{path}:{i + 1}: table row outside a table -- renders as literal text")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("roots", nargs="*", default=["."], help="directories to scan (default: .)")
    args = ap.parse_args()
    roots = args.roots or ["."]

    findings = []
    scanned = 0
    for root in roots:
        # os.walk on a path that does not exist yields nothing and the check passes,
        # which is the same failure as a soak reporting `compared=0`: a guard that
        # checked nothing must never look like a guard that found nothing.
        if not os.path.isdir(root):
            print(f"error: not a directory: {root}", file=sys.stderr)
            return 2
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d
                for d in dirnames
                if d not in (".git", "target", ".claude", "node_modules", "helios-bsc-grant")
            ]
            for name in filenames:
                if name.endswith(".md"):
                    scanned += 1
                    findings += check(os.path.join(dirpath, name))
    if not scanned:
        print("error: no markdown files found; refusing to report a pass", file=sys.stderr)
        return 2
    for f in findings:
        print(f)
    if findings:
        print()
        print(f"{len(findings)} markdown table row(s) render as literal text.")
        return 1
    print(f"markdown tables OK ({scanned} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
