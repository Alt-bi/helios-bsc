#!/usr/bin/env python3
"""Capture BSC header JSON fixtures for Phase 0 / Demo Slice.

Usage:
  python scripts/capture_headers.py --rpc URL --from-block N --count 5 --out fixtures/mainnet/

Does not verify seals — consensus crate will consume these later.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import urllib.request


def rpc(url: str, method: str, params: list) -> dict:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "helios-bsc-phase0-capture",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--from-block", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path("fixtures/mainnet"))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    for i in range(args.count):
        n = args.from_block + i
        nhex = hex(n)
        res = rpc(args.rpc, "eth_getBlockByNumber", [nhex, False])
        block = res.get("result")
        if not block:
            raise SystemExit(f"missing block {n}: {res}")
        path = args.out / f"header_{n}.json"
        path.write_text(json.dumps(block, indent=2), encoding="utf-8")
        print("wrote", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
