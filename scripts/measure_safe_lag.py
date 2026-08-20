#!/usr/bin/env python3
"""Measure live confirmation-depth lag: min window to see 15 distinct miners."""

from __future__ import annotations

import json
import urllib.request

RPC = "https://bsc-mainnet.public.blastapi.io"
WINDOW = 200
THRESHOLD = 15


def rpc_batch(calls: list) -> list:
    body = json.dumps(calls).encode()
    req = urllib.request.Request(
        RPC,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "helios-bsc-phase0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    tip_hex = rpc_batch(
        [{"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}]
    )[0]["result"]
    tip = int(tip_hex, 16)
    print(f"tip {tip}", flush=True)

    headers = []
    start = tip - WINDOW + 1
    for batch_start in range(start, tip + 1, 40):
        batch_end = min(batch_start + 39, tip)
        calls = [
            {
                "jsonrpc": "2.0",
                "id": n,
                "method": "eth_getBlockByNumber",
                "params": [hex(n), False],
            }
            for n in range(batch_start, batch_end + 1)
        ]
        rows = rpc_batch(calls)
        rows.sort(key=lambda r: r["id"])
        for r in rows:
            b = r.get("result") or {}
            headers.append(
                {
                    "n": int(b["number"], 16),
                    "miner": (b.get("miner") or "").lower(),
                    "diff": int(b.get("difficulty") or "0x0", 16),
                }
            )
        print(f"fetched {headers[0]['n'] if headers else '?'}..{headers[-1]['n']}", flush=True)

    headers.sort(key=lambda h: h["n"])
    miners = [h["miner"] for h in headers]
    diffs = [h["diff"] for h in headers]

    def distinct_in(slice_miners: list[str]) -> int:
        return len(set(slice_miners))

    print("\n# distinct miners in last K blocks from tip")
    for k in (64, 80, 96, 100, 108, 110, 112, 116, 120, 128, 160, 200):
        d = distinct_in(miners[-k:])
        in_turn = sum(1 for x in diffs[-k:] if x == 2)
        print(f"K={k:3d} distinct={d:2d} in_turn={in_turn:3d}/{k}  need15={'YES' if d >= THRESHOLD else 'no'}")

    def lag_to_threshold(seq: list[str], th: int = THRESHOLD) -> int | None:
        seen: set[str] = set()
        for i, m in enumerate(reversed(seq), start=1):
            seen.add(m)
            if len(seen) >= th:
                return i
        return None

    print("\n# min lookback from several tips to reach 15 distinct")
    for back in range(0, 81, 20):
        seq = miners[: len(miners) - back] if back else miners
        lag = lag_to_threshold(seq)
        print(f"from tip-{back:2d}: lag={lag}")

    # How many distinct after exactly 112 (Ankr window)
    print("\n# would Ankr-window (112) contain a Safe ancestor?")
    d112 = distinct_in(miners[-112:])
    lag = lag_to_threshold(miners)
    print(f"distinct in last 112 = {d112}")
    print(f"newest-Safe lag from current tip = {lag}")
    if lag is not None:
        print(f"Ankr 112 can prove newest Safe? {lag <= 112}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
