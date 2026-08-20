#!/usr/bin/env python3
"""Probe BSC eth_getProof capability for helios-bsc Phase 0 matrix.

Usage:
  python scripts/probe_eth_get_proof.py --rpc https://bsc-dataseed.binance.org
  python scripts/probe_eth_get_proof.py --rpc URL --address 0x... --block latest

Exit 0 always after printing JSON result rows (failures are data for the matrix).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

# Well-known BSC token / system-ish address for probe (WBNB)
WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"


def rpc(url: str, method: str, params: list, timeout: float = 30.0) -> dict:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "helios-bsc-phase0-probe"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def probe_block(url: str, address: str, block_id) -> dict:
    try:
        tip = rpc(url, "eth_blockNumber", [])
        tip_hex = tip.get("result")
        out = {"tip": tip_hex, "block_param": block_id}
        # Resolve hash/number variants
        if block_id == "by_number" and tip_hex:
            block_param: object = tip_hex
            out["resolved"] = tip_hex
        elif block_id == "by_hash" and tip_hex:
            blk = rpc(url, "eth_getBlockByNumber", [tip_hex, False])
            h = (blk.get("result") or {}).get("hash")
            block_param = h
            out["resolved"] = h
        else:
            block_param = block_id
            out["resolved"] = block_id

        proof = rpc(url, "eth_getProof", [address, [], block_param])
        if "error" in proof:
            out["ok"] = False
            out["error"] = proof["error"]
        else:
            res = proof.get("result") or {}
            out["ok"] = bool(res.get("accountProof") or res.get("storageHash"))
            out["keys"] = list(res.keys())[:12]
        return out
    except Exception as e:
        return {"block_param": block_id, "ok": False, "error": str(e)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rpc", required=True, help="BSC HTTP JSON-RPC URL")
    ap.add_argument("--address", default=WBNB)
    args = ap.parse_args()

    rows = []
    for label in ("latest", "finalized", "safe", "by_number", "by_hash"):
        rows.append({"label": label, **probe_block(args.rpc, args.address, label)})

    print(json.dumps({"rpc": args.rpc, "address": args.address, "probes": rows}, indent=2))
    passed = [r for r in rows if r.get("ok") and r["label"] in ("by_number", "by_hash")]
    print(
        "\n# SUMMARY: hash/number pass="
        + str(bool(passed))
        + ("  ← Phase 0 gate OK candidate" if passed else "  ← need other provider or Alt F"),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
