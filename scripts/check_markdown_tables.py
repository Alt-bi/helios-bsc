#!/usr/bin/env python3
r"""Refuse a markdown table row that will not render as its author meant it to.

Two rules, both found by a row that was wrong on the page and right in the diff.

**A row outside a table.** STATUS.md's milestone table had two stray blank lines in it.
GitHub renders a `| a | b |` line that follows a blank line as literal text, not as a
table row -- so the four newest milestones, including the container image and both guards
added that day, showed up as pipe-soup on the page every reader lands on first. `cargo
test` cannot see that, no link checker sees it, and nobody reading the diff of a one-row
addition sees it either. The rule: a line starting with `|` must be preceded either by
another `|` line or by nothing (it opens the table, and the line after it must be the
header delimiter).

**A row with the wrong number of cells.** `docs/rpc-matrix.md` -- the document that says
what this client verifies, refuses and passes through -- carried a `Block-tag hex` row
with two cells under a three-column header. GFM does not complain: it pads the row with
an empty cell at the end, which silently shifts every cell one column left. So the whole
note rendered inside the **Trust** column, and the row's actual trust class was blank.
The text was all there and all correct, and the table said something else. The rule: a
row's cell count must equal its header's. Pipes inside `code spans` and `\|` escapes do
not separate cells, so neither counts here.
"""
import argparse
import io
import os
import re
import sys

DELIM = re.compile(r"^\|[\s:|-]+\|\s*$")


def cells(row: str) -> int:
    """Cell count of one GFM table row.

    A `|` only separates cells when it is neither escaped nor inside a code span, which
    is why this is a scan and not a `str.split`. The leading and trailing pipes are
    delimiters rather than empty cells, so they are stripped first.
    """
    row = row.strip()
    if row.startswith("|"):
        row = row[1:]
    if row.endswith("|") and not row.endswith("\\|"):
        row = row[:-1]
    count = 1
    tick = False
    escaped = False
    for ch in row:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
        elif ch == "`":
            tick = not tick
        elif ch == "|" and not tick:
            count += 1
    return count


def check(path: str) -> list[str]:
    lines = io.open(path, encoding="utf-8").read().replace("\r\n", "\n").split("\n")
    bad = []
    fenced = False
    # Cell count of the header of the table currently being read, if any.
    width = None
    for i, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            fenced = not fenced
        if fenced or not line.startswith("|"):
            width = None
            continue
        prev = lines[i - 1] if i else ""
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if not prev.startswith("|"):
            # Opening a table: the next line has to be the header delimiter.
            if not DELIM.match(nxt):
                bad.append(
                    f"{path}:{i + 1}: table row outside a table -- renders as literal text"
                )
                width = None
                continue
            width = cells(line)
            continue
        # A delimiter row is allowed to be written loosely; it is not a data row.
        if DELIM.match(line):
            continue
        if width is not None and cells(line) != width:
            bad.append(
                f"{path}:{i + 1}: row has {cells(line)} cells, its header has {width} -- "
                f"GFM pads the row and every cell renders one column out of place"
            )
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
        print(f"{len(findings)} markdown table row(s) will not render as written.")
        return 1
    print(f"markdown tables OK ({scanned} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
