#!/usr/bin/env python3
"""Prove a refactor moved code without editing it.

Splitting a 4,700-line file is exactly the kind of change where a one-character edit
hides in a 4,700-line diff, and nobody reads that diff line by line. `cargo test`
passing is evidence, not proof: the suite covers what somebody thought to test.

So this compares the *content* before and after as a multiset of tokens across all the
files involved. Tokens rather than lines because rustfmt re-wraps any signature the
moment `pub(crate) ` pushes it past the column limit, and a line-level check drowns in
that noise; a token multiset is blind to wrapping and still catches a flipped
comparison, a changed constant, or a dropped negation.

Code and comments are compared separately. Code must be identical. Comments may be
*gained* -- a split adds module headers -- but never lost, because documentation
quietly dropped in a move is the same defect as code quietly dropped in one.

Deliberately ignored, because a split cannot happen without them:

  * `mod` / `use` lines, and the visibility prefixes (`pub(crate)`, `pub(super)`) an
    item needs once it lives in a child module;
  * `impl <Type> {` wrappers, one per module that received methods, and their braces;
  * `//!` module headers.

Usage:

    scripts/check_pure_move.py <git-ref> <old-path> <new-path> [<new-path> ...]

For the rpc_server split:

    python scripts/check_pure_move.py origin/main bin/helios-bsc/src/rpc_server.rs \
        bin/helios-bsc/src/rpc_server.rs bin/helios-bsc/src/rpc_server/*.rs
"""

import collections
import io
import re
import subprocess
import sys

SKIP_LINE = re.compile(r"^\s*(pub(\(\w+\))? )?(mod|use) |^\s*//!")
VIS = re.compile(r"pub\((crate|super|self)\)\s*")
IMPL_OPEN = re.compile(r"^\s*impl\s+\w+\s*\{\s*$")
TOKEN = re.compile(r"\w+|\S")
NL = chr(10)
CR = chr(13)
BACKSLASH = chr(92)


def strip_comment(line):
    """Split a line into (code, comment), respecting string literals.

    A naive cut at `//` mangles every URL in the file, and this codebase is full of
    them.
    """
    out = []
    i = 0
    in_str = False
    while i < len(line):
        c = line[i]
        if in_str:
            if c == BACKSLASH:
                out.append(line[i : i + 2])
                i += 2
                continue
            if c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == "/" and line[i : i + 2] == "//":
                return "".join(out), line[i:]
        out.append(c)
        i += 1
    return "".join(out), ""


def lines_of(text):
    return text.replace(CR + NL, NL).split(NL)


def drop_trailing_commas(toks):
    """Remove a comma that sits immediately before a closing delimiter.

    rustfmt puts a short signature on one line and a long one across several, and
    the wrapped form gains a trailing comma after its last parameter. Adding
    `pub(crate) ` to a signature is exactly what pushes it over the limit, so that
    comma is punctuation the formatter chose rather than something anybody edited.
    Normalised away on both sides; a comma anywhere else still counts.
    """
    out = []
    for i, t in enumerate(toks):
        if t == "," and i + 1 < len(toks) and toks[i + 1] in (")", "]", "}", ">"):
            continue
        out.append(t)
    return out


def split_tokens(text):
    """Return (code tokens, comment tokens) as multisets."""
    code_stream = []
    comments = collections.Counter()
    for line in lines_of(text):
        if not line.strip() or SKIP_LINE.match(line):
            continue
        if IMPL_OPEN.match(line):
            continue
        body, comment = strip_comment(line)
        code_stream += TOKEN.findall(VIS.sub("", body))
        for tok in TOKEN.findall(comment):
            comments[tok] += 1
    return collections.Counter(drop_trailing_commas(code_stream)), comments


def impl_count(text):
    return sum(1 for line in lines_of(text) if IMPL_OPEN.match(line))


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    ref, old_path = sys.argv[1], sys.argv[2]
    new_paths = sys.argv[3:]

    old_raw = subprocess.run(
        ["git", "show", ref + ":" + old_path], capture_output=True, check=True
    ).stdout.decode("utf-8")
    before, before_c = split_tokens(old_raw)

    after = collections.Counter()
    after_c = collections.Counter()
    new_impls = 0
    for p in new_paths:
        text = io.open(p, encoding="utf-8").read()
        c, cm = split_tokens(text)
        after += c
        after_c += cm
        new_impls += impl_count(text)

    # The `impl X {` openers are skipped above; their closing braces cannot be told
    # apart from any other closing brace, so discount one per wrapper the split added.
    net = new_impls - impl_count(old_raw)
    if net > 0:
        after["}"] -= net
    elif net < 0:
        before["}"] += net

    lost = before - after
    gained = after - before
    lost_c = before_c - after_c

    print(ref + ":" + old_path + "  ->  " + str(len(new_paths)) + " file(s)")
    print("  code tokens before: " + str(sum(before.values())))
    print("  code tokens after:  " + str(sum(after.values())))
    print("  impl blocks the split added: " + str(net))
    print(
        "  comment tokens: "
        + str(sum(before_c.values()))
        + " -> "
        + str(sum(after_c.values()))
    )

    ok = True
    if lost or gained:
        ok = False
        print("")
        print("CODE removed (" + str(sum(lost.values())) + " tokens):")
        for tok, n in lost.most_common(60):
            print("  -" + str(n) + "x " + tok)
        print("")
        print("CODE added (" + str(sum(gained.values())) + " tokens):")
        for tok, n in gained.most_common(60):
            print("  +" + str(n) + "x " + tok)
    if lost_c:
        ok = False
        print("")
        print(
            "COMMENT text removed ("
            + str(sum(lost_c.values()))
            + " tokens) -- a move must not lose documentation:"
        )
        for tok, n in lost_c.most_common(40):
            print("  -" + str(n) + "x " + tok)

    if ok:
        added_c = sum((after_c - before_c).values())
        print("")
        print("PURE MOVE: every code token survived, and none was added.")
        if added_c:
            print(
                "Comments gained "
                + str(added_c)
                + " tokens (the new module headers); none was lost."
            )
        return 0
    print("")
    print("NOT a pure move. Each token above is a real edit, or a gap in this check.")
    return 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
