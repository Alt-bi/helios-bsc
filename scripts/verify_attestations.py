#!/usr/bin/env python3
"""Gather real evidence about Parlia Fast Finality vote attestations on BSC mainnet.

Every BSC header may carry a BLS vote attestation inside ``extraData``. That
attestation names a *source* (already justified) and a *target* (newly justified)
block; the source of the newest attestation is the BLS-**finalized** head. If
that head sits a handful of blocks behind the tip, this client could serve
``finalized`` far closer to the tip than the confirmation-depth Safe rule does
today (~106-112 blocks), which also shrinks the ``eth_getProof`` provider-window
problem in ``docs/proof-provider-matrix.md``.

This script walks N consecutive recent headers, parses the attestation out of
``extraData`` exactly like ``crates/helios-bsc-config/src/extra.rs`` does,
RLP-decodes it with a strict decoder (no trailing bytes, no truncation, no
non-canonical integers), and then checks the protocol invariants:

  * target == the direct parent (``number-1`` / ``parentHash``)
  * source continuity (block N's source == block N-1's target)
  * vote participation >= ceil(21*2/3) = 14
  * ``Extra`` length <= 256

Chain data only; nothing here verifies BLS signatures — that is Rust's job.
Exit code is non-zero iff a hard invariant is violated.

## Repro
  python scripts/verify_attestations.py --rpc https://bsc-dataseed.bnbchain.org --blocks 120
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.error
import urllib.request

# extraData layout — mirrors crates/helios-bsc-config/src/{lib,extra}.rs
EXTRA_VANITY = 32
EXTRA_SEAL = 65
VALIDATOR_NUMBER_SIZE = 1
VALIDATOR_BYTES = 68  # 20-byte address + 48-byte BLS vote key
TURN_LENGTH_SIZE = 1  # Bohr
EPOCH_LENGTH = 1000  # Maxwell — what mainnet uses today

VALIDATOR_COUNT = 21
QUORUM = -(-VALIDATOR_COUNT * 2 // 3)  # ceil(21*2/3) = 14
EXTRA_CAP = 256  # protocol cap on VoteAttestation.Extra

# Current confirmation-depth Safe rule this client ships with.
SAFE_LAG_LO, SAFE_LAG_HI = 106, 112


# --------------------------------------------------------------------------
# RPC
# --------------------------------------------------------------------------


def rpc(url: str, method: str, params: list, retries: int = 4):
    """One JSON-RPC call. No batching: bsc-dataseed rejects batch arrays."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = ""
    for attempt in range(retries):
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                # Several BSC public endpoints 403 a bare Python-urllib UA.
                "User-Agent": "helios-bsc-verify-attestations",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            last = f"{type(exc).__name__}: {exc}"
            time.sleep(0.5 * (attempt + 1))
            continue
        if "error" in payload:
            raise SystemExit(f"upstream error on {method}: {payload['error']}")
        return payload.get("result")
    raise SystemExit(f"{url}: {method} failed after {retries} tries — {last}")


# --------------------------------------------------------------------------
# Strict RLP
# --------------------------------------------------------------------------


class RlpError(ValueError):
    """Malformed or non-canonical RLP."""


def _read_len(buf: bytes, pos: int, lenlen: int) -> tuple[int, int]:
    if pos + lenlen > len(buf):
        raise RlpError("truncated length header")
    raw = buf[pos : pos + lenlen]
    if raw[0] == 0:
        raise RlpError("non-canonical length prefix (leading zero byte)")
    return int.from_bytes(raw, "big"), pos + lenlen


def _decode_item(buf: bytes, pos: int):
    if pos >= len(buf):
        raise RlpError("truncated payload")
    prefix = buf[pos]

    if prefix < 0x80:  # single byte, itself
        return buf[pos : pos + 1], pos + 1

    if prefix <= 0xB7:  # short string
        ln = prefix - 0x80
        start, end = pos + 1, pos + 1 + ln
        if end > len(buf):
            raise RlpError("truncated short string")
        data = buf[start:end]
        if ln == 1 and data[0] < 0x80:
            raise RlpError("non-canonical single-byte string")
        return data, end

    if prefix <= 0xBF:  # long string
        ln, start = _read_len(buf, pos + 1, prefix - 0xB7)
        if ln <= 55:
            raise RlpError("non-canonical long string (length <= 55)")
        end = start + ln
        if end > len(buf):
            raise RlpError("truncated long string")
        return buf[start:end], end

    if prefix <= 0xF7:  # short list
        ln = prefix - 0xC0
        start, end = pos + 1, pos + 1 + ln
    else:  # long list
        ln, start = _read_len(buf, pos + 1, prefix - 0xF7)
        if ln <= 55:
            raise RlpError("non-canonical long list (length <= 55)")
        end = start + ln

    if end > len(buf):
        raise RlpError("truncated list")
    items, cur = [], start
    while cur < end:
        item, cur = _decode_item(buf, cur)
        items.append(item)
    if cur != end:
        raise RlpError("list payload overruns its declared length")
    return items, end


def rlp_decode(buf: bytes):
    """Decode exactly one RLP item; reject trailing bytes."""
    item, pos = _decode_item(buf, 0)
    if pos != len(buf):
        raise RlpError(f"{len(buf) - pos} trailing byte(s) after RLP item")
    return item


def rlp_uint(b, field: str) -> int:
    if not isinstance(b, (bytes, bytearray)):
        raise RlpError(f"{field}: expected string, got list")
    if len(b) > 8:
        raise RlpError(f"{field}: {len(b)} bytes is too wide for uint64")
    if b and b[0] == 0:
        raise RlpError(f"{field}: non-canonical integer (leading zero byte)")
    return int.from_bytes(b, "big")


def rlp_bytes(b, field: str, size: int | None = None) -> bytes:
    if not isinstance(b, (bytes, bytearray)):
        raise RlpError(f"{field}: expected string, got list")
    if size is not None and len(b) != size:
        raise RlpError(f"{field}: expected {size} bytes, got {len(b)}")
    return bytes(b)


# --------------------------------------------------------------------------
# extraData / attestation parsing
# --------------------------------------------------------------------------


def unhex(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def attestation_bytes(extra: bytes, number: int) -> bytes:
    """Raw RLP attestation slice out of extraData (Bohr layout on epoch blocks)."""
    if len(extra) < EXTRA_VANITY + EXTRA_SEAL:
        raise RlpError(f"extraData shorter than vanity+seal ({len(extra)} bytes)")
    mid = extra[EXTRA_VANITY : len(extra) - EXTRA_SEAL]
    if number % EPOCH_LENGTH != 0:
        return mid
    if not mid:
        raise RlpError("epoch extraData missing validator count")
    n = mid[0]
    vals_end = VALIDATOR_NUMBER_SIZE + n * VALIDATOR_BYTES
    if n == 0 or len(mid) < vals_end + TURN_LENGTH_SIZE:
        raise RlpError(f"epoch extraData missing validator records (n={n}, mid={len(mid)})")
    return mid[vals_end + TURN_LENGTH_SIZE :]


def parse_attestation(raw: bytes) -> dict:
    """RLP -> {vote_address_set, agg_signature, source/target, extra_len}."""
    top = rlp_decode(raw)
    if not isinstance(top, list) or len(top) != 4:
        raise RlpError(f"attestation: expected a 4-item list, got {type(top).__name__}")
    vote_set = rlp_uint(top[0], "VoteAddressSet")
    agg = rlp_bytes(top[1], "AggSignature", 96)
    data = top[2]
    if not isinstance(data, list) or len(data) != 4:
        raise RlpError("attestation.Data: expected a 4-item list")
    extra = rlp_bytes(top[3], "Extra")
    return {
        "vote_address_set": vote_set,
        "popcount": bin(vote_set).count("1"),
        "agg_signature": "0x" + agg.hex(),
        "source_number": rlp_uint(data[0], "SourceNumber"),
        "source_hash": "0x" + rlp_bytes(data[1], "SourceHash", 32).hex(),
        "target_number": rlp_uint(data[2], "TargetNumber"),
        "target_hash": "0x" + rlp_bytes(data[3], "TargetHash", 32).hex(),
        "extra_len": len(extra),
    }


# --------------------------------------------------------------------------
# Reporting helpers
# --------------------------------------------------------------------------


def histogram(values: list[int], label: str, indent: str = "  ") -> None:
    if not values:
        print(f"{indent}(no samples)")
        return
    counts: dict[int, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    widest = max(counts.values())
    for k in sorted(counts):
        c = counts[k]
        bar = "#" * max(1, round(40 * c / widest))
        print(f"{indent}{label}={k:<6d} {c:5d}  {bar}")


def stats_line(values: list[int]) -> str:
    if not values:
        return "n/a"
    return (
        f"min={min(values)} max={max(values)} "
        f"median={statistics.median(values):g} mean={statistics.fmean(values):.2f}"
    )


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rpc", default="https://bsc-dataseed.bnbchain.org")
    ap.add_argument("--blocks", type=int, default=200, help="consecutive headers to walk")
    ap.add_argument("--from-block", type=int, default=None, help="newest block (default: tip)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if args.blocks < 1:
        raise SystemExit("--blocks must be >= 1")

    log = (lambda *a, **k: None) if args.json else print

    tip = int(rpc(args.rpc, "eth_blockNumber", []), 16)
    high = args.from_block if args.from_block is not None else tip
    low = max(0, high - args.blocks + 1)
    log(f"walking {low}..{high} ({high - low + 1} headers) via {args.rpc}  [tip {tip}]")

    rows: list[dict] = []
    for number in range(low, high + 1):
        blk = rpc(args.rpc, "eth_getBlockByNumber", [hex(number), False])
        if not blk:
            raise SystemExit(f"block {number} not returned by upstream")
        row: dict = {
            "number": number,
            "parent_hash": blk["parentHash"].lower(),
            "hash": blk["hash"].lower(),
            "miner": (blk.get("miner") or "").lower(),
            "present": False,
            "parse_error": None,
            "attestation": None,
        }
        try:
            raw = attestation_bytes(unhex(blk["extraData"]), number)
            if raw:
                row["present"] = True
                row["attestation"] = parse_attestation(raw)
        except RlpError as exc:
            row["parse_error"] = str(exc)
        rows.append(row)
        if not args.json and (number - low) % 20 == 0:
            log(f"  fetched {number} ({number - low + 1}/{high - low + 1})", flush=True)

    # ---- invariants -------------------------------------------------------
    target_violations: list[str] = []
    source_violations: list[str] = []
    quorum_violations: list[str] = []
    extra_violations: list[str] = []
    parse_errors: list[str] = []

    just_lags: list[int] = []
    final_lags: list[int] = []
    popcounts: list[int] = []
    extra_lens: list[int] = []
    present = 0

    by_number = {r["number"]: r for r in rows}
    for r in rows:
        n = r["number"]
        if r["parse_error"]:
            parse_errors.append(f"block {n}: {r['parse_error']}")
            continue
        if not r["present"]:
            continue
        present += 1
        a = r["attestation"]

        if a["target_number"] != n - 1:
            target_violations.append(
                f"block {n}: target_number={a['target_number']} (expected {n - 1})"
            )
        if a["target_hash"] != r["parent_hash"]:
            target_violations.append(
                f"block {n}: target_hash={a['target_hash']} parentHash={r['parent_hash']}"
            )

        prev = by_number.get(n - 1)
        if prev is not None and prev["present"] and prev["attestation"]:
            want = prev["attestation"]["target_number"]
            if a["source_number"] != want:
                source_violations.append(
                    f"block {n}: source_number={a['source_number']} but block {n - 1} "
                    f"justified {want}"
                )
            elif a["source_hash"] != prev["attestation"]["target_hash"]:
                source_violations.append(
                    f"block {n}: source_hash={a['source_hash']} but block {n - 1} "
                    f"target_hash={prev['attestation']['target_hash']}"
                )

        if a["popcount"] < QUORUM:
            quorum_violations.append(
                f"block {n}: popcount={a['popcount']} < quorum {QUORUM}"
            )
        if a["extra_len"] > EXTRA_CAP:
            extra_violations.append(f"block {n}: extra_len={a['extra_len']} > {EXTRA_CAP}")

        just_lags.append(n - a["target_number"])
        final_lags.append(n - a["source_number"])
        popcounts.append(a["popcount"])
        extra_lens.append(a["extra_len"])

    total = len(rows)
    absent = total - present - len(parse_errors)
    hard_fail = bool(
        target_violations or source_violations or quorum_violations or extra_violations
    )

    if args.json:
        print(
            json.dumps(
                {
                    "rpc": args.rpc,
                    "tip": tip,
                    "range": [low, high],
                    "headers": total,
                    "with_attestation": present,
                    "without_attestation": absent,
                    "parse_errors": parse_errors,
                    "justification_lag": just_lags,
                    "finalization_lag": final_lags,
                    "popcounts": popcounts,
                    "extra_lens": extra_lens,
                    "quorum": QUORUM,
                    "safe_lag_window": [SAFE_LAG_LO, SAFE_LAG_HI],
                    "violations": {
                        "target_not_parent": target_violations,
                        "source_discontinuity": source_violations,
                        "below_quorum": quorum_violations,
                        "extra_too_long": extra_violations,
                    },
                    "blocks": rows,
                },
                indent=2,
            )
        )
        return 1 if hard_fail else 0

    print()
    print("=" * 72)
    print(f"  Parlia vote attestations -- blocks {low}..{high}  ({total} headers)")
    print("=" * 72)
    print(f"  endpoint                 {args.rpc}")
    print(f"  chain tip at start       {tip}")
    print()
    pct = 100.0 * present / total if total else 0.0
    print(f"  attestation present      {present}/{total}  ({pct:.1f}%)")
    print(f"  attestation absent       {absent}")
    print(f"  parse errors             {len(parse_errors)}")
    print()
    print(f"  target == direct parent  {'OK' if not target_violations else 'VIOLATED'}"
          f"  ({len(target_violations)} violation(s))")
    print(f"  source chain continuity  {'OK' if not source_violations else 'VIOLATED'}"
          f"  ({len(source_violations)} violation(s))")
    print(f"  popcount >= {QUORUM:<12d} {'OK' if not quorum_violations else 'VIOLATED'}"
          f"  ({len(quorum_violations)} violation(s))")
    print(f"  extra_len <= {EXTRA_CAP:<11d} {'OK' if not extra_violations else 'VIOLATED'}"
          f"  ({len(extra_violations)} violation(s))")
    print()
    print(f"  justification lag        {stats_line(just_lags)}   (number - target_number)")
    print(f"  finalization  lag        {stats_line(final_lags)}   (number - source_number)")
    print(f"  vote participation       {stats_line(popcounts)}  of {VALIDATOR_COUNT}")
    if popcounts:
        meet = sum(1 for p in popcounts if p >= QUORUM)
        print(f"  blocks meeting quorum    {meet}/{len(popcounts)}  (threshold {QUORUM})")
    print(f"  max Extra length         {max(extra_lens) if extra_lens else 0} (cap {EXTRA_CAP})")

    print("\n  # justification lag histogram (number - target_number)")
    histogram(just_lags, "lag", indent="    ")
    print("\n  # finalization lag histogram (number - source_number)")
    histogram(final_lags, "lag", indent="    ")
    print("\n  # vote participation histogram (popcount of VoteAddressSet)")
    histogram(popcounts, "votes", indent="    ")

    # ---- the headline comparison -----------------------------------------
    print("\n  # BLS finality vs confirmation-depth Safe rule")
    if final_lags:
        med = statistics.median(final_lags)
        worst = max(final_lags)
        print(f"    BLS-finalized head sits    {med:g} blocks behind (median), "
              f"{worst} worst-case")
        print(f"    confirmation-depth Safe    {SAFE_LAG_LO}-{SAFE_LAG_HI} blocks behind")
        if worst:
            print(f"    BLS is closer to tip by    ~{SAFE_LAG_LO - worst}-"
                  f"{SAFE_LAG_HI - worst} blocks (worst-case BLS vs Safe window)")
            print(f"    speedup factor             ~{SAFE_LAG_LO / worst:.0f}-"
                  f"{SAFE_LAG_HI / worst:.0f}x")
        print(f"    => serving `finalized` from attestations would land inside any")
        print(f"       eth_getProof provider window (see docs/proof-provider-matrix.md)")
    else:
        print("    no attestations observed - cannot compare")

    for name, items in (
        ("target != parent", target_violations),
        ("source discontinuity", source_violations),
        ("below quorum", quorum_violations),
        ("extra > cap", extra_violations),
        ("parse errors (soft)", parse_errors),
    ):
        if items:
            print(f"\n  ! {name} ({len(items)}):")
            for line in items[:25]:
                print(f"      - {line}")
            if len(items) > 25:
                print(f"      ... and {len(items) - 25} more")

    print()
    if hard_fail:
        print("FAIL -- a hard attestation invariant does not hold on live mainnet")
        return 1
    print("PASS -- every hard attestation invariant holds across the walked range")
    return 0


if __name__ == "__main__":
    sys.exit(main())
