#!/usr/bin/env python3
"""Capture eth_getProof + header stateRoot for MPT fixtures.

Usage:
  python scripts/capture_proof.py --rpc URL --address 0x... --out fixtures/mainnet/proof_usdc.json
"""

from __future__ import annotations

import argparse
import json
import urllib.request


def rpc(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "helios-bsc-capture-proof"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode())
    if "error" in data:
        raise SystemExit(f"rpc error: {data['error']}")
    return data["result"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--address", required=True)
    ap.add_argument("--lag", type=int, default=0)
    ap.add_argument(
        "--slot",
        action="append",
        default=[],
        help="Storage slot hex (repeatable). Empty = account proof only.",
    )
    ap.add_argument("--out", required=True)
    ap.add_argument(
        "--code-out",
        help="Also write eth_getCode hex for this address/block (keccak vs proof codeHash).",
    )
    args = ap.parse_args()

    tip = int(rpc(args.rpc, "eth_blockNumber", []), 16)
    n = tip - args.lag
    hx = hex(n)
    blk = rpc(args.rpc, "eth_getBlockByNumber", [hx, False])
    proof = rpc(args.rpc, "eth_getProof", [args.address, args.slot, hx])
    out = {
        "address": args.address,
        "number": n,
        "hash": blk["hash"],
        "stateRoot": blk["stateRoot"],
        "slots": args.slot,
        "proof": proof,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f)
    nodes = proof.get("accountProof") or []
    sp = proof.get("storageProof") or []
    print(
        f"wrote {args.out} block={n} account_nodes={len(nodes)} "
        f"storage_slots={len(sp)} balance={proof.get('balance')}"
    )
    if args.code_out:
        code = rpc(args.rpc, "eth_getCode", [args.address, hx])
        with open(args.code_out, "w", encoding="utf-8") as f:
            f.write(code if isinstance(code, str) else "0x")
        print(f"wrote {args.code_out} code_len={len(code) if isinstance(code, str) else 0}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
