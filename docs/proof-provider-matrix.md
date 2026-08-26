# eth_getProof provider matrix (Phase 0 exit gate)

Wallet-mode Safe is the newest block with **≥15 distinct subsequent sealers**, not a hard `tip-120` offset. `15 * turnLength` (=120 @ T=8) is the in-turn **upper** estimate. Live measure (2026-08-18, `scripts/measure_safe_lag.py`): newest-Safe lag **108–112**. Windows of 100 / 110 only see ~13 / ~14 sealers — not Safe. Provider proofs tagged only `latest` / `finalized` **cannot** match Safe `stateRoot`.

## Requirement

Demo Slice / verified reads need:

- `eth_getProof(address, storageKeys, blockNumberOrHash)` where the block is the **Safe** hash or number (**≥ ~120 blocks behind tip**), **or**
- Alt F: own untrusted full/fast node that retains that window (or archive).

**Tag-only = gate fail. Tip-only hash/number = gate fail.**

## Matrix (2026-08-18)

Probed with `scripts/probe_eth_get_proof.py` plus a lag sweep (0 / 8 / 16 / 32 / 64 / 96 / 128 / 192 / 240). Address: WBNB `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`.

| Provider / URL | Auth | by `latest` | by **number** | by **hash** | Historical window | Notes | Pass? |
|----------------|------|-------------|---------------|-------------|-------------------|-------|-------|
| `https://bsc-dataseed.binance.org` | none | rate-limit | rate-limit | rate-limit | — | `-32005 limit exceeded` on proofs | no |
| `https://bsc-dataseed1.binance.org` | none | rate-limit | rate-limit | rate-limit | — | same | no |
| `https://bsc-dataseed2.defibit.io` | none | rate-limit | rate-limit | rate-limit | — | same | no |
| `https://bsc-dataseed.bnbchain.org` | none | rate-limit | rate-limit | rate-limit | — | same | no |
| `https://bsc.publicnode.com` | none | **OK** | fail window | fail window | tag-only | `-32602 distance to target block exceeds maximum proof window` on hash/number even at tip | no |
| `https://bsc-rpc.publicnode.com` | none | **OK** | fail window | fail window | tag-only | same as publicnode | no |
| `https://1rpc.io/bnb` | none | missing trie | missing trie | missing trie | 0 | pruned | no |
| `https://binance.llamarpc.com` | none | — | — | — | — | TLS EOF | no |
| `https://bsc.drpc.org` | none | — | — | — | — | HTTP 429 | no |
| `https://bsc.meowrpc.com` | none | — | — | — | — | HTTP 429 after tip | no |
| `https://bsc.blockpi.network/v1/rpc/public` | none | — | — | — | — | HTTP 521 | no |
| `https://endpoints.omniatech.io/v1/bsc/mainnet/public` | none | — | — | — | — | HTTP 521 | no |
| `https://rpc.ankr.com/bsc` | **API key** | auth | auth | auth | ? | `Unauthorized` without key | pending key |
| Ankr personal (free, 2026-08-19) | **key** | **OK** | **OK ≤~108** | often `not supported` | **~108, jitter** | Number-first proofs. 45s header walk ages Safe out of window unless we catch-up. ~3 proofs/burst then prune. Live: WBNB MPT vs BlastAPI match at Safe. Do not commit the URL. | **partial** (Safe knife-edge) |
| `https://bsc-mainnet.nodereal.io/v1/64a9df0874fb4a93b9d0a3849de012d3` | public MegaNode demo key | **OK** | **OK ≤96** | — | **~96; FAIL at 120** | Official public key (2000 CU/min). Same window as BlastAPI — **Safe (~120) not covered** | **no** |
| `https://rpc-bsc.48.club` | none | — | missing trie | — | 0 | even tip-by-number fails | no |
| `https://bsc.rpc.blxrbdn.com` | none | — | missing trie | — | 0 | even tip-by-number fails | no |
| `https://bnb.rpc.subquery.network/public` | none | — | — | — | — | TLS EOF | no |
| **`https://bsc-mainnet.public.blastapi.io`** | none | **OK** | **OK at tip** | **OK at tip** | **~96 blocks; FAIL at 128** | Best public so far. **Safe (~120) is outside the window.** Tip proof saved as `fixtures/mainnet/proof_wbnb_tip.json` (MPT unit tests only) | **no** (window too shallow) |
| QuickNode personal (free, 2026-08-18) | **key** | **OK** | **OK at tip only** | fail window | **5 blocks** (`-32615 eth_getProof is limited to a 5 range, upgrade`) | Correct BSC HTTPS endpoint. Free plan cannot reach Safe (~120). Do not commit the URL. | **no** |
| Alt F (self full/fast) | local | | | | full / archive | only if paid matrix fails | not provisioned |

## Gate verdict

**PASS on the default build (fast finality). PARTIAL PASS under `--finality confirmation-depth`.**

> Re-framed 2026-08-25. The measurements below were taken on 2026-08-21, when fast
> finality was opt-in and confirmation depth was the default; that flipped on 2026-08-25.
> The numbers are unchanged — what changed is which column describes a stock `run`.

The gate had been stuck since 2026-08-19 on one number: confirmation-depth Safe needs a
proof ~112 blocks back, and no free provider retains state that deep. BLS fast finality
moves the head to **2 blocks**, so the requirement becomes a ~3-block window — and the
free, keyless providers clear that easily.

Measured 2026-08-21 (`scripts/sweep_proof_window.py`, then the client itself):

| | Default (confirmation depth) | `run --finality fast` |
|--|--|--|
| Required by-number/by-hash window | ~112 blocks | **~3 blocks** |
| `bsc-mainnet.public.blastapi.io` (free, **no key**) | **FAIL** — window ends between lag 64 and 96 | **PASS** — OK by number *and* hash at lag 0/2/3/5/8/16/32/64 |

End-to-end on that free endpoint with `--finality fast`, head at `tip - 2`:

- `eth_getBalance`, `eth_getStorageAt` (WBNB slot 0 → "Wrapped BNB") and `eth_call`
  (`totalSupply`) all returned MPT-verified values.
- Differential against **two independent blind oracles** (publicnode, meowrpc) at a pinned
  block: **8 addresses, 8 match, 0 mismatch, 0 skip.**

So Alt F (self-hosted full node) is **no longer mandatory** for a verified read, and no
paid key is needed either. Since 2026-08-25 that is the stock configuration rather than an
opt-in. Only `--finality confirmation-depth` still needs a ≥112-block window, which is why
this is a PASS with a qualifier rather than an unconditional one.

Two caveats that have not changed:

- **Tag-only providers still fail, at any lag.** `bsc-rpc.publicnode.com` rejects an
  explicit block id even at the tip (`-32602 distance to target block exceeds maximum
  proof window`). Fast finality changes the required *depth*, not whether a provider can
  address a block at all.
- A **rate-limited** probe is not a window verdict. `bsc-dataseed.bnbchain.org` answers
  `limit exceeded` to every proof; that says nothing about its capability, and the sweep
  script now reports it as inconclusive rather than as tag-only.

Next:

1. Re-probe the paid/keyed rows (Ankr / NodeReal / QuickNode) against the **≥3-block**
   requirement — QuickNode free was rejected for a 5-block window that is now ample.
2. The ≥24h differential soak, which is also the gate for making `--finality fast` the
   default.

## What Fast Finality changes here (2026-08-21)

**Every Pass? column in the table above was measured against the ~112-block requirement,
which is now what `--finality confirmation-depth` asks for — not what a stock `run` asks
for.** The default needs ~3.

Re-swept 2026-08-21 with `scripts/sweep_proof_window.py`, which now probes the
fast-finality lags (0/2/3/5) alongside the deep ones and reports by-hash next to by-number:

| Provider | by-number at lag ≤3 | deepest by-number | Verdict |
|----------|--------------------|-------------------|---------|
| `bsc-mainnet.public.blastapi.io` | **OK** (also by hash) | lag 64 OK, 96 fails | **passes the default (fast finality)**, fails `--finality confirmation-depth` |
| `bsc-rpc.publicnode.com` | FAIL | none — fails at the tip | **tag-only**; no finality rule helps |
| `bsc.meowrpc.com` | FAIL (`missing trie node`) | none by number | fails both; by-hash answers were inconsistent across probes, so it is load-balanced across nodes with different pruning |
| `bsc-dataseed.bnbchain.org` | `limit exceeded` | — | **inconclusive**, rate limit not a window verdict |

The rows still worth re-probing under ≥3 are the ones rejected purely on depth: NodeReal
(~96) and especially **QuickNode free, whose 5-block window was a hard fail at 112 and is
ample at 2**.

## The matrix was right and the README was not (2026-08-26)

Re-measured against live mainnet, by number, address zero, one probe per lag:

| Provider | tag `latest` | lag 2 | lag 64 | lag 112 | lag 128 |
|---|---|---|---|---|---|
| `bsc-mainnet.public.blastapi.io` | OK | **OK** | **OK** | **OK** | `missing trie node` |
| `bsc-rpc.publicnode.com` | OK | refused | refused | refused | refused |
| `bsc.drpc.org` | OK | rate-limited | OK | rate-limited | rate-limited |

publicnode's refusal is the same `-32602 distance to target block exceeds maximum proof
window` this file has recorded since 2026-08-18, at every lag including the tip. Nothing
changed. blastapi's window has *widened* since the 2026-08-21 sweep — 112 answers now
where 96 failed then — which is a reminder that these are provider-side settings and not
protocol facts.

**What was new is where that host was named.** `README.md`, `docs/quickstart.md` and
`docs/deploy.md` all told a first-time reader to run
`--upstream https://bsc-rpc.publicnode.com` — the host this table marks *tag-only, no*.
Verified end to end: the same differential soak, changing only `--upstream`, gives
`compared=0` with a `proof_verification_failed` on the first `eth_getBalance` against
publicnode, and `compared=1466 match=1466 mismatch=0` against blastapi. So the getting
started command did not work, and this file had said why for eight days.

Two fixes. The commands now name a measured proof provider and keep publicnode where it
is genuinely good — as `--checkpoint-oracle` and `--backup`, neither of which needs a
proof. And `run` now probes its upstream at startup and prints the diagnosis itself, so
the next provider that turns out to be tag-only does not need anybody to read this file:

```
!!! This upstream serves eth_getProof for the tag `latest` but refuses it at
!!! its own verified head 118191284 (lag 2):
!!!   rpc error: {"code":-32602,"message":"distance to target block exceeds maximum proof window"}
```

## Re-probe notes (2026-08-21)

Two traps that cost time when re-running this matrix — neither is a client bug:

- **Send a `User-Agent`.** BlastAPI, publicnode and meowrpc now answer **403** to a bare `Python-urllib` / default-`curl` request, and **200** to the same request with any UA set. This reads exactly like an IP ban or a new key requirement and is neither. Every `scripts/*.py` sets one, and the client sends `helios-bsc` (`bin/helios-bsc/src/upstream.rs`), so only ad-hoc one-liners are affected. Re-confirmed working from the client UA against all four hosts.
- **A non-batching upstream cannot keep up with 0.45 s blocks.** Measured 2026-08-21: with
  `bsc-dataseed.bnbchain.org` the sync poller holds the chain lock almost continuously
  (one round-trip per header, ~4 new blocks per 1.8 s poll), and `helios_bsc_syncStatus`
  then blocks for **90 s+**. The same build against `bsc-rpc.publicnode.com`, which does
  batch, answers in **0.8–1.8 s**. This is an upstream property, not a client defect —
  but it is a second, independent reason not to pick a non-batching endpoint for the soak.
- **`bsc-dataseed.bnbchain.org` serves headers but rejects batching.** Both the parallel fetch and the JSON-RPC batch array fail, so the client falls back to one request per header — a cold 130-header walk becomes 130 sequential round-trips. Fine as a header source for fixture capture; **do not pick it as a soak upstream**. (Its `eth_getProof` is still `-32005 limit exceeded`, as the matrix already records.)

## Repro

```bash
python scripts/probe_eth_get_proof.py --rpc https://bsc-mainnet.public.blastapi.io
```

Mutated-proof fail case: **covered in CI** (`helios-bsc-execution` + `helios-bsc-mock` + `Node::handle` adversarial tests). Live Safe-lag proofs still depend on the provider window (Ankr ~112).

## Receipts are a second capability, and no free host has both (2026-08-25)

The table above measures `eth_getProof`. Since receipts began binding to
`transactionsRoot`, a verified read of `eth_getTransactionReceipt`, `eth_getBlockReceipts`
or `eth_getLogs` also needs `eth_getBlockReceipts` and `eth_getRawTransactionByHash` from
the data plane. Measured on the same three keyless hosts:

| Host | `eth_getProof` | `eth_getBlockReceipts` |
|------|----------------|------------------------|
| `bsc-mainnet.public.blastapi.io` | **OK** | `401 Unauthorized` (needs a key) |
| `bsc-dataseed.bnbchain.org` | `limit exceeded` | **OK** |
| `bsc-rpc.publicnode.com` | tag-only — fails at any lag | **OK** |

**No free public host serves both.** The fix needs no new feature: `--backup` already
exists as transport failover, and it covers exactly this — a call the primary refuses is
retried on the second host. Verified live with
`--upstream https://bsc-mainnet.public.blastapi.io --backup https://bsc-rpc.publicnode.com`:
proofs came from the first, receipts from the second, and a full soak round reported
`compared=454 match=454 mismatch=0`, including 432 receipt-field checks.

The backup is **not** a trust oracle and this does not make it one. Whichever host answers,
the receipts are still re-encoded to consensus RLP and bound to the sealed `receiptsRoot`,
and the envelopes to `transactionsRoot`. Failover changes who is asked, never what is
checked.

