#!/usr/bin/env python3
"""Sweep eth_getProof at tip-lag offsets, by number **and** by hash.

Two thresholds matter, and they are far apart:

  * confirmation-depth Safe needs a window of ~112 blocks
  * BLS fast finality (`run --finality fast`) needs only ~3

so the default lag set covers both ends. A provider that fails at 112 but passes
at 2-3 is unusable for the default build and usable with `--finality fast`.

By-hash is probed alongside by-number because some endpoints serve only tags:
those reject *any* explicit block, at any distance including the tip, and no
finality rule can rescue them. See docs/proof-provider-matrix.md.

Do not put API keys in this file.

Repro:
  python scripts/sweep_proof_window.py --rpc https://bsc-mainnet.public.blastapi.io
  python scripts/sweep_proof_window.py --rpc URL --lags 0,2,3,5 --json
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request

WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"
# Fast-finality range first (2 is the live lag), then the confirmation-depth range.
LAGS = (0, 2, 3, 5, 8, 16, 32, 64, 96, 104, 108, 112)
# `ceil(2N/3)` finality lands 2 blocks back; allow a block of slack for a slow poll.
FAST_FINALITY_LAG = 3


def rpc(url: str, method: str, params: list) -> dict:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        # Several BSC endpoints answer 403 to a bare Python-urllib request and 200 to the
        # same request with any UA set. See docs/proof-provider-matrix.md.
        headers={"Content-Type": "application/json", "User-Agent": "helios-bsc-sweep"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def _is_throttle(detail: str) -> bool:
    """A rate limit tells us nothing about the provider's proof window."""
    d = (detail or "").lower()
    return any(
        s in d
        for s in ("limit exceeded", "429", "too many requests", "rate limit", "quota", "403")
    )


def probe(url: str, address: str, block_id: str) -> tuple[str, str]:
    """Return (verdict, detail). Verdict is OK / EMPTY / FAIL / HTTP."""
    try:
        proof = rpc(url, "eth_getProof", [address, [], block_id])
    except Exception as e:  # transport, TLS, HTTP status — all data for the matrix
        return "HTTP", str(e)
    if "error" in proof:
        err = proof["error"]
        return "FAIL", str(err.get("message", err) if isinstance(err, dict) else err)
    res = proof.get("result") or {}
    # An empty accountProof is not an inclusion proof; treat it as a miss, not a pass.
    return ("OK", "") if res.get("accountProof") else ("EMPTY", "no accountProof")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--address", default=WBNB)
    ap.add_argument(
        "--lags",
        default=",".join(str(x) for x in LAGS),
        help="comma-separated tip offsets to probe",
    )
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    lags = sorted({int(x) for x in args.lags.split(",") if x.strip()})
    tip = int(rpc(args.rpc, "eth_blockNumber", [])["result"], 16)

    rows = []
    for lag in lags:
        n = tip - lag
        by_number, num_detail = probe(args.rpc, args.address, hex(n))

        # Only ask for the hash when the height itself is reachable; otherwise the
        # extra round-trip tells us nothing new.
        by_hash, hash_detail = "SKIP", "block header not fetched"
        try:
            blk = rpc(args.rpc, "eth_getBlockByNumber", [hex(n), False]).get("result")
            if blk and blk.get("hash"):
                by_hash, hash_detail = probe(args.rpc, args.address, blk["hash"])
        except Exception as e:
            by_hash, hash_detail = "HTTP", str(e)

        rows.append(
            {
                "lag": lag,
                "number": n,
                "by_number": by_number,
                "by_number_detail": num_detail,
                "by_hash": by_hash,
                "by_hash_detail": hash_detail,
            }
        )
        if not args.json:
            det = num_detail or hash_detail
            det = f"  {det[:90]}" if det else ""
            print(
                f"lag={lag:3d} n={n}  by_number={by_number:5s} by_hash={by_hash:5s}{det}",
                flush=True,
            )

    ok_number = {r["lag"] for r in rows if r["by_number"] == "OK"}
    deepest = max(ok_number) if ok_number else None
    nothing_worked = not ok_number and not any(r["by_hash"] == "OK" for r in rows)
    # "Nothing worked" has two very different causes and they must not be conflated:
    # a rate limit says nothing about the provider's capability, while a rejection of
    # the block id itself is a permanent gate fail. Only the latter is tag-only.
    throttled = nothing_worked and all(
        _is_throttle(r["by_number_detail"]) and _is_throttle(r["by_hash_detail"])
        for r in rows
        if r["by_number"] != "OK"
    )
    tag_only = nothing_worked and not throttled
    fast_ok = any(r["lag"] <= FAST_FINALITY_LAG and r["by_number"] == "OK" for r in rows)
    conf_ok = any(r["lag"] >= 112 and r["by_number"] == "OK" for r in rows)

    verdict = {
        "rpc": args.rpc,
        "tip": tip,
        "deepest_by_number_lag": deepest,
        "tag_only": tag_only,
        "usable_with_fast_finality": fast_ok,
        "usable_with_confirmation_depth": conf_ok,
        "rows": rows,
    }
    if args.json:
        print(json.dumps(verdict, indent=2))
        return 0

    verdict["throttled"] = throttled
    print("\n# VERDICT", file=sys.stderr)
    if throttled:
        print(
            "  RATE-LIMITED / INCONCLUSIVE: every probe was refused by a quota, not by a\n"
            "  block-id rejection. This says nothing about the provider's proof window —\n"
            "  re-run later or with a key before recording a verdict.",
            file=sys.stderr,
        )
    elif tag_only:
        print(
            "  TAG-ONLY: rejects explicit block ids at every lag including the tip.\n"
            "  No finality rule fixes this — the provider cannot serve a proof at a\n"
            "  specific block at all. Gate fail for both modes.",
            file=sys.stderr,
        )
    else:
        print(f"  deepest by-number lag that worked: {deepest}", file=sys.stderr)
        print(
            f"  --finality fast (needs <= {FAST_FINALITY_LAG}): "
            f"{'PASS' if fast_ok else 'FAIL'}",
            file=sys.stderr,
        )
        print(
            f"  default confirmation depth (needs >= 112): {'PASS' if conf_ok else 'FAIL'}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
