#!/usr/bin/env python3
"""Verify committed fixtures against live BSC mainnet.

Fixtures are the ground truth for every consensus test in this tree. A fixture
that was hand-edited, truncated, or captured from a lying upstream would make
those tests pass while proving nothing, so re-check them against the chain:

  * ``header_*.json``  — every field must match ``eth_getBlockByNumber``.
  * ``proof_*.json``   — the bound ``stateRoot`` / block hash must match the
    real header at that height (proof *contents* are verified in Rust against
    that root; here we only prove the binding is real).
  * ``wbnb_code.hex``  — must equal live ``eth_getCode`` for WBNB.

This reads public chain data only. It is a fixture-authenticity check, not a
consensus check: `cargo test` still does the seal/MPT verification.

Usage:
  python scripts/verify_fixtures.py --rpc https://bsc-dataseed.bnbchain.org
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.request

WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"

# Present in an RPC block but not part of a stored header fixture.
SKIP_FIELDS = {"transactions", "uncles", "size", "totalDifficulty"}


def rpc(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "helios-bsc-verify-fixtures"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        payload = json.loads(resp.read().decode())
    if "error" in payload:
        raise SystemExit(f"upstream error on {method}: {payload['error']}")
    return payload.get("result")


def norm(v):
    """Compare hex quantities by value so 0x0 vs 0x00 is not a false diff."""
    if isinstance(v, str):
        s = v.lower()
        # Quantities only; 20/32-byte data stays a literal string compare.
        if s.startswith("0x") and 2 < len(s) < 42:
            try:
                return hex(int(s, 16))
            except ValueError:
                return s
        return s
    return v


def check_headers(url: str, fixdir: pathlib.Path) -> list[str]:
    fails = []
    for path in sorted(fixdir.glob("header_*.json")):
        local = json.loads(path.read_text(encoding="utf-8"))
        number = int(local["number"], 16)
        live = rpc(url, "eth_getBlockByNumber", [hex(number), False])
        if not live:
            fails.append(f"{path.name}: block {number} not returned by upstream")
            continue
        diffs = [
            f"{k}: fixture={local[k]!r} live={live.get(k)!r}"
            for k in local
            if k not in SKIP_FIELDS and norm(local[k]) != norm(live.get(k))
        ]
        if diffs:
            fails.append(f"{path.name} (block {number}):\n      " + "\n      ".join(diffs))
        else:
            print(f"  ok  {path.name} (block {number}) matches live chain")
    return fails


def check_proofs(url: str, fixdir: pathlib.Path) -> list[str]:
    fails = []
    for path in sorted(fixdir.glob("proof_*.json")):
        d = json.loads(path.read_text(encoding="utf-8"))
        number = d.get("number", d.get("blockNumber"))
        if number is None:
            fails.append(f"{path.name}: no bound block number")
            continue
        live = rpc(url, "eth_getBlockByNumber", [hex(int(number)), False])
        if not live:
            fails.append(f"{path.name}: block {number} not returned by upstream")
            continue
        if norm(d["stateRoot"]) != norm(live["stateRoot"]):
            fails.append(
                f"{path.name}: stateRoot fixture={d['stateRoot']} live={live['stateRoot']}"
            )
            continue
        claimed_hash = d.get("hash", d.get("blockHash"))
        if claimed_hash and norm(claimed_hash) != norm(live["hash"]):
            fails.append(f"{path.name}: blockHash fixture={claimed_hash} live={live['hash']}")
            continue
        print(f"  ok  {path.name} bound to real block {number} (stateRoot + hash)")
    return fails


def check_code(url: str, fixdir: pathlib.Path) -> list[str]:
    path = fixdir / "wbnb_code.hex"
    if not path.exists():
        return []
    local = path.read_text(encoding="utf-8").strip()
    live = rpc(url, "eth_getCode", [WBNB, "latest"])
    if not live or live.lower() != local.lower():
        return [f"wbnb_code.hex differs from live eth_getCode ({len(local)} vs {len(live or '')} chars)"]
    print(f"  ok  wbnb_code.hex matches live eth_getCode ({len(local)} chars)")
    return []


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rpc", default="https://bsc-dataseed.bnbchain.org")
    ap.add_argument("--fixtures", type=pathlib.Path, default=pathlib.Path("fixtures/mainnet"))
    args = ap.parse_args()

    if not args.fixtures.is_dir():
        raise SystemExit(f"no fixture dir: {args.fixtures}")

    print(f"verifying {args.fixtures} against {args.rpc}")
    fails = check_headers(args.rpc, args.fixtures)
    fails += check_proofs(args.rpc, args.fixtures)
    fails += check_code(args.rpc, args.fixtures)

    if fails:
        print("\nFAIL — fixtures do not match the live chain:")
        for f in fails:
            print("  -", f)
        return 1
    print("\nPASS — every fixture matches live BSC mainnet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
