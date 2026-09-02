#!/usr/bin/env python3
"""Check the fork schedule against the geth release it was transcribed from.

Every fork constant in `crates/helios-bsc-config/src/lib.rs` was copied by hand out of
`params/config.go` in `bnb-chain/bsc`. They decide which consensus rules this client
applies at a given header, so a single mistyped digit does not crash anything -- it makes
the client verify a block under the wrong rules and answer confidently. That is the worst
failure this codebase has: a wrong verified answer rather than a refusal.

`upstream-pin.yml` already watches for the day upstream *changes* one of these files. It
cannot notice that a number was copied wrong in the first place, because it only ever
diffs upstream against upstream. This checks the other direction: that what this tree
says the schedule is, is what the pinned release says it is.

The pin is read out of the same Rust file as the constants, so the comparison can never
drift onto some other commit. Pass `--file` to compare against a local copy instead of
fetching, which is how the failure path is tested.

Exit codes are distinct on purpose. **1** is a real mismatch. **2** is a parse that could
not compare what it promised to. **3** is only "upstream was unreachable", which is not a
finding about this repository -- it lets `ci.yml` treat a network blip as a notice while
the weekly `upstream-pin` run, where reaching upstream is the whole job, still fails on
it. A guard that goes red for someone else's outage is a guard that gets muted.

Scope: the mainnet fields in `BSCChainConfig`. Parlia's own parameters -- epoch length,
turn length, block interval -- live in `consensus/parlia`, are not in this file, and are
not checked here; the module docstring in the Rust file says where they come from.
"""

import argparse
import io
import re
import subprocess
import sys

CONFIG_RS = "crates/helios-bsc-config/src/lib.rs"
RAW = "https://raw.githubusercontent.com/bnb-chain/bsc/{commit}/params/config.go"

# Rust constant -> the `BSCChainConfig` field it was copied from.
#
# `OSAKA_MENDEL_TIME` is one Rust constant for two geth fields, so the name itself is a
# claim that the two are equal. It is checked below rather than assumed.
MAPPING = {
    "LONDON_BLOCK": "LondonBlock",
    "LUBAN_BLOCK": "LubanBlock",
    "PLATO_BLOCK": "PlatoBlock",
    "CANCUN_TIME": "CancunTime",
    "BOHR_TIME": "BohrTime",
    "PRAGUE_TIME": "PragueTime",
    "LORENTZ_TIME": "LorentzTime",
    "MAXWELL_TIME": "MaxwellTime",
    "FERMI_TIME": "FermiTime",
    "OSAKA_MENDEL_TIME": "OsakaTime",
    "PASTEUR_TIME": "PasteurTime",
}
# Fields that must agree with each other upstream for a Rust constant to stand for both.
ALIASES = [("OsakaTime", "MendelTime")]

RUST_CONST = re.compile(r"^pub const ([A-Z0-9_]+): u64 = ([0-9_]+);", re.M)
RUST_STR = re.compile(r'^pub const ([A-Z0-9_]+): &str = "([^"]+)";', re.M)
GO_FIELD = re.compile(
    r"^\s*([A-Za-z0-9]+):\s*(?:big\.NewInt\((\d+)\)|newUint64\((\d+)\))", re.M
)


def rust_facts(path: str) -> tuple[dict[str, int], dict[str, str]]:
    text = io.open(path, encoding="utf-8").read()
    return (
        {m.group(1): int(m.group(2).replace("_", "")) for m in RUST_CONST.finditer(text)},
        {m.group(1): m.group(2) for m in RUST_STR.finditer(text)},
    )


def go_bsc_mainnet(text: str) -> dict[str, int]:
    """The `BSCChainConfig` literal only -- `params/config.go` also holds Chapel and Rialto.

    Matching to the closing `}` of the literal would need brace counting through nested
    structs; the next `XxxChainConfig = &ChainConfig{` is a simpler boundary and just as
    exact, and if the file ever stops having one the length check below fails loudly
    rather than silently comparing a truncated block.
    """
    head = "BSCChainConfig = &ChainConfig{"
    start = text.find(head)
    if start < 0:
        raise SystemExit("error: no BSCChainConfig literal in params/config.go")
    # Past the opening line, or the boundary search below matches this literal's own
    # header and hands back an empty block.
    rest = text[start + len(head) :]
    nxt = re.search(r"^\s*[A-Za-z0-9]+ChainConfig = &ChainConfig\{", rest, re.M)
    block = rest[: nxt.start()] if nxt else rest
    return {
        m.group(1): int(m.group(2) or m.group(3))
        for m in GO_FIELD.finditer(block)
        if (m.group(2) or m.group(3))
    }


class Unreachable(Exception):
    """Upstream could not be read. Not a finding about this repository."""


def fetch(url: str) -> str:
    # curl rather than urllib: it is what `upstream-pin.yml` already uses for the same
    # host, so one proxy or TLS quirk cannot make the two jobs disagree about the file.
    out = subprocess.run(
        ["curl", "-sSfL", "-m", "60", url], capture_output=True, text=True, check=False
    )
    if out.returncode != 0:
        raise Unreachable(f"could not fetch {url}: {out.stderr.strip()}")
    return out.stdout


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--file", help="local params/config.go instead of fetching the pin")
    ap.add_argument("--config-rs", default=CONFIG_RS)
    args = ap.parse_args()

    consts, strings = rust_facts(args.config_rs)
    commit = strings.get("BSC_UPSTREAM_COMMIT")
    tag = strings.get("BSC_UPSTREAM_TAG", "?")
    if not commit:
        print(f"error: no BSC_UPSTREAM_COMMIT in {args.config_rs}", file=sys.stderr)
        return 2

    if args.file:
        go_text = io.open(args.file, encoding="utf-8").read()
        source = args.file
    else:
        source = RAW.format(commit=commit)
        try:
            go_text = fetch(source)
        except Unreachable as e:
            print(f"error: {e}", file=sys.stderr)
            return 3
    fields = go_bsc_mainnet(go_text)

    if fields.get("ChainID") != 56:
        print(
            f"error: that literal has ChainID {fields.get('ChainID')}, not 56 -- "
            "the parse picked up the wrong network",
            file=sys.stderr,
        )
        return 2

    print(f"pin: {tag} ({commit[:12]})")
    print(f"source: {source}\n")

    bad = []
    for rust_name, go_name in sorted(MAPPING.items()):
        if rust_name not in consts:
            bad.append(f"{rust_name} is gone from {args.config_rs}")
            continue
        if go_name not in fields:
            bad.append(f"{go_name} is not in the pinned BSCChainConfig")
            continue
        ours, theirs = consts[rust_name], fields[go_name]
        mark = "ok " if ours == theirs else "BAD"
        print(f"  {mark} {rust_name:<18} {ours:<12} {go_name} = {theirs}")
        if ours != theirs:
            bad.append(f"{rust_name} is {ours}; {go_name} at {tag} is {theirs}")

    for a, b in ALIASES:
        if fields.get(a) != fields.get(b):
            bad.append(
                f"{a} ({fields.get(a)}) and {b} ({fields.get(b)}) no longer coincide, "
                f"so one Rust constant can no longer stand for both"
            )

    # A guard that compared nothing must never look like a guard that found nothing --
    # the same rule the soak applies to `compared=0`.
    compared = sum(1 for r, g in MAPPING.items() if r in consts and g in fields)
    if compared != len(MAPPING):
        print(
            f"\nerror: compared {compared} of {len(MAPPING)} constants; "
            "refusing to report a pass",
            file=sys.stderr,
        )
        for b in bad:
            print(f"  {b}", file=sys.stderr)
        return 2

    if bad:
        print("\nFAIL: the fork schedule does not match the release it was copied from.")
        for b in bad:
            print(f"  {b}")
        print(
            "\nA wrong fork boundary makes this client verify a block under the wrong "
            "rules and answer confidently. Fix the constant, or re-pin deliberately."
        )
        return 1

    print(f"\nall {compared} fork constants match {tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
