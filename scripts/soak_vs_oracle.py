#!/usr/bin/env python3
"""Soak: local verified eth_getBalance vs an independent oracle RPC.

Operator script (not a CI gate). Needs a running `helios-bsc run` and a public
oracle that can serve historical balances. Oracle must be independent of the
proof/header upstream (default BlastAPI, not Ankr).

Prefer `helios-bsc soak --oracle URL` when you want MPT-verified local balances
without a second process. This script diffs the local JSON-RPC surface.

Usage:
  python scripts/soak_vs_oracle.py
  python scripts/soak_vs_oracle.py --once
  python scripts/soak_vs_oracle.py --rounds 120 --interval 30

Env:
  HELIOS_BSC_LOCAL   default http://127.0.0.1:8545
  HELIOS_BSC_ORACLE  default https://bsc-mainnet.public.blastapi.io

Exit 0 if every compared address matches (skips allowed when the oracle cannot
serve historical state). Exit 1 on mismatch or local RPC error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "helios-bsc-soak"
TIMEOUT_S = 30.0

# Mix of well-known BSC tokens, DEX, lending, treasury, system contracts.
ADDRESSES: list[tuple[str, str]] = [
    ("WBNB", "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"),
    ("USDT", "0x55d398326f99059fF775485246999027B3197955"),
    ("USDC", "0x8AC76a51cc950d9822D68b83fe1Ad97B32Cd580d"),
    ("Cake", "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82"),
    ("BUSD", "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56"),
    ("PancakeRouter", "0x10ED43C718714eb63d5aA57B78B54704E256024E"),
    ("PancakeFactory", "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73"),
    ("VenusUnitroller", "0xfD36E2c2a6789Db23113685031d7F16329158384"),
    ("VenusVBNB", "0xA07c5b74C9B18179ce657c4d74e5CE8C674C96a3"),
    ("VenusTreasury", "0xF322942f644A996A617BD29c16bd7d231d9F35E9"),
    ("BinanceHot", "0xe2fc31F816A9b94326492132018C3aEcC4a93aE1"),
    ("TokenHub", "0x0000000000000000000000000000000000001004"),
    ("ETH", "0x2170Ed0880ac9A755fd29B2688956BD959F933F8"),
    ("DAI", "0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3"),
    ("XVS", "0xcF6BB5389c92Bdda8a3747Ddb454cB7a64626C63"),
    ("BTCB", "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c"),
    ("ValidatorSet", "0x0000000000000000000000000000000000001000"),
    ("Slash", "0x0000000000000000000000000000000000001001"),
    ("SystemReward", "0x0000000000000000000000000000000000001002"),
]

# Path segment that looks like an API key / hex secret.
_HEX_KEY = re.compile(r"^[0-9a-fA-F]{32,}$")


class LocalRpcError(Exception):
    pass


class OracleSkip(Exception):
    pass


def redact_url(url: str) -> str:
    """Host + path, with 32+ hex path segments (API keys) replaced."""
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return "<unparseable-url>"
    parts = [( "***" if _HEX_KEY.fullmatch(seg) else seg) for seg in p.path.split("/")]
    # Drop query/fragment: those often carry keys even when the path does not.
    return urllib.parse.urlunsplit((p.scheme, p.netloc, "/".join(parts), "", ""))


def rpc(url: str, method: str, params: list, timeout: float = TIMEOUT_S) -> dict:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def rpc_error_text(err: object) -> str:
    if isinstance(err, dict):
        msg = err.get("message")
        if msg:
            return str(msg)
        return json.dumps(err, separators=(",", ":"))
    return str(err)


def parse_qty(value: object) -> str:
    """Normalize a hex quantity (strip leading zeros)."""
    if not isinstance(value, str) or not value.lower().startswith("0x"):
        raise ValueError(f"not a hex quantity: {value!r}")
    n = int(value, 16)
    return hex(n)


def parse_block_number(value: object) -> int:
    if isinstance(value, bool) or value is None:
        raise ValueError(f"bad block number: {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    raise ValueError(f"bad block number: {value!r}")


def local_rpc(url: str, method: str, params: list) -> object:
    try:
        resp = rpc(url, method, params)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        raise LocalRpcError(f"{method}: {e}") from e
    if "error" in resp:
        raise LocalRpcError(f"{method}: {rpc_error_text(resp['error'])}")
    return resp.get("result")


def fetch_sync_status(local_url: str) -> tuple[int, str, dict]:
    result = local_rpc(local_url, "helios_bsc_syncStatus", [])
    if not isinstance(result, dict):
        raise LocalRpcError("helios_bsc_syncStatus: result is not an object")
    if result.get("safe") is None:
        raise LocalRpcError("helios_bsc_syncStatus: missing safe")
    safe_hash = result.get("safeHash") or result.get("safe_hash")
    if not safe_hash:
        raise LocalRpcError("helios_bsc_syncStatus: missing safeHash")
    safe_num = parse_block_number(result["safe"])
    return safe_num, str(safe_hash), result


def fetch_local_balance(local_url: str, addr: str) -> str:
    result = local_rpc(local_url, "eth_getBalance", [addr, "latest"])
    try:
        return parse_qty(result)
    except ValueError as e:
        raise LocalRpcError(f"eth_getBalance({addr}): {e}") from e


def fetch_oracle_balance(oracle_url: str, addr: str, safe_num: int, safe_hash: str) -> tuple[str, str]:
    """Balance at the local Safe height. Prefer number hex, then hash."""
    number_hex = hex(safe_num)
    last_reason = "oracle cannot serve historical balance"
    for param in (number_hex, safe_hash):
        try:
            resp = rpc(oracle_url, "eth_getBalance", [addr, param])
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            last_reason = f"eth_getBalance({param}): {e}"
            continue
        if "error" in resp:
            last_reason = f"eth_getBalance({param}): {rpc_error_text(resp['error'])}"
            continue
        result = resp.get("result")
        if result is None:
            last_reason = f"eth_getBalance({param}): null result"
            continue
        try:
            return parse_qty(result), param
        except ValueError as e:
            last_reason = f"eth_getBalance({param}): {e}"
            continue

    # Block exists but state is missing → historical-only skip, not a mismatch.
    try:
        blk = rpc(oracle_url, "eth_getBlockByNumber", [number_hex, False])
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        raise OracleSkip(f"{last_reason}; eth_getBlockByNumber: {e}") from e
    if "error" in blk:
        raise OracleSkip(f"{last_reason}; eth_getBlockByNumber: {rpc_error_text(blk['error'])}")
    if not blk.get("result"):
        raise OracleSkip(
            f"{last_reason}; eth_getBlockByNumber({number_hex}): block not found"
        )
    raise OracleSkip(f"{last_reason} (block exists; no historical state)")


def run_round(
    local_url: str,
    oracle_url: str,
    round_i: int,
    rounds: int,
) -> tuple[int, int, int, int]:
    """Returns (compared, match, mismatch, skip). Local errors raise."""
    safe_num, safe_hash, status = fetch_sync_status(local_url)
    tip = status.get("tip")
    lag = status.get("lag")
    tip_s = str(tip) if tip is not None else "?"
    lag_s = str(lag) if lag is not None else "?"
    print(
        f"== round {round_i}/{rounds}  safe={safe_num}  {safe_hash}  tip={tip_s}  lag={lag_s}",
        flush=True,
    )

    compared = match = mismatch = skip = 0
    name_w = max(len(n) for n, _ in ADDRESSES)
    for name, addr in ADDRESSES:
        local_qty = fetch_local_balance(local_url, addr)
        try:
            oracle_qty, used = fetch_oracle_balance(oracle_url, addr, safe_num, safe_hash)
        except OracleSkip as e:
            skip += 1
            print(f"  {name:<{name_w}}  SKIP  {e}", flush=True)
            continue
        compared += 1
        if int(local_qty, 16) == int(oracle_qty, 16):
            match += 1
            print(
                f"  {name:<{name_w}}  local={local_qty}  oracle={oracle_qty}  OK  @{used}",
                flush=True,
            )
        else:
            mismatch += 1
            print(
                f"  {name:<{name_w}}  local={local_qty}  oracle={oracle_qty}  MISMATCH  @{used}",
                flush=True,
            )
    return compared, match, mismatch, skip


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--local",
        default=os.environ.get("HELIOS_BSC_LOCAL", "http://127.0.0.1:8545"),
        help="helios-bsc run endpoint (env HELIOS_BSC_LOCAL)",
    )
    ap.add_argument(
        "--oracle",
        default=os.environ.get(
            "HELIOS_BSC_ORACLE", "https://bsc-mainnet.public.blastapi.io"
        ),
        help="independent oracle RPC (env HELIOS_BSC_ORACLE)",
    )
    ap.add_argument("--interval", type=float, default=30.0, help="seconds between rounds")
    ap.add_argument("--rounds", type=int, default=4, help="number of rounds (default 4)")
    ap.add_argument("--once", action="store_true", help="single pass (overrides --rounds)")
    args = ap.parse_args()

    if args.interval < 0:
        print("error: --interval must be >= 0", file=sys.stderr)
        return 1
    rounds = 1 if args.once else args.rounds
    if rounds < 1:
        print("error: --rounds must be >= 1", file=sys.stderr)
        return 1

    print("# helios-bsc soak vs independent oracle", flush=True)
    print(f"local   {redact_url(args.local)}", flush=True)
    print(f"oracle  {redact_url(args.oracle)}", flush=True)
    print(
        f"rounds  {rounds}  interval {args.interval}s  addresses {len(ADDRESSES)}",
        flush=True,
    )

    tot_cmp = tot_ok = tot_bad = tot_skip = 0
    local_err: str | None = None
    try:
        for i in range(1, rounds + 1):
            try:
                c, ok, bad, sk = run_round(args.local, args.oracle, i, rounds)
            except LocalRpcError as e:
                local_err = str(e)
                print(f"  LOCAL_ERROR  {e}", flush=True)
                break
            tot_cmp += c
            tot_ok += ok
            tot_bad += bad
            tot_skip += sk
            if i < rounds and args.interval > 0:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("interrupted", flush=True)
        local_err = local_err or "interrupted"

    print(
        f"# SUMMARY  compared={tot_cmp}  match={tot_ok}  mismatch={tot_bad}"
        f"  skip={tot_skip}"
        + (f"  local_err={local_err}" if local_err else ""),
        flush=True,
    )
    if local_err:
        return 1
    if tot_bad:
        return 1
    if tot_cmp == 0:
        print("# no addresses compared (oracle historical skips only) — fail-closed", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
