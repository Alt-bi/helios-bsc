#!/usr/bin/env python3
"""Sweep eth_getProof by number at tip-lag offsets. Do not put API keys in this file."""

from __future__ import annotations

import argparse
import json
import urllib.request

WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"
LAGS = (0, 8, 16, 32, 48, 64, 80, 96, 104, 108, 110, 112)


def rpc(url: str, method: str, params: list) -> dict:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "helios-bsc-sweep"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--address", default=WBNB)
    args = ap.parse_args()
    tip = int(rpc(args.rpc, "eth_blockNumber", [])["result"], 16)
    print(f"tip {tip}", flush=True)
    for lag in LAGS:
        n = tip - lag
        hx = hex(n)
        try:
            proof = rpc(args.rpc, "eth_getProof", [args.address, [], hx])
        except Exception as e:
            print(f"lag={lag:3d} n={n} HTTP {e}", flush=True)
            continue
        if "error" in proof:
            err = proof["error"]
            msg = err.get("message", err) if isinstance(err, dict) else err
            print(f"lag={lag:3d} n={n} FAIL {msg}", flush=True)
        else:
            res = proof.get("result") or {}
            ok = bool(res.get("accountProof"))
            print(f"lag={lag:3d} n={n} {'OK' if ok else 'EMPTY'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
