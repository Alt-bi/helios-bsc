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

**PARTIAL PASS (2026-08-19).** Ankr by-number proved WBNB at live Safe when lag ≤~108 after catch-up (`probe-safe` GATE PASS vs BlastAPI oracle). Soak **10 unique / 0 mismatch** vs BlastAPI (`helios-bsc soak --min-unique 10`). Neighbor-leaf proofs for unused addresses are **exclusion** (empty account), not a walker bug. BlastAPI stays oracle-only (~96). Tag-only still fails the gate.

Next (operator order from design):

1. Probe **one paid** provider with archive or `debug`/`full` state (Ankr / NodeReal / QuickNode / Alchemy / Chainstack).
2. If that also cannot prove `tip-120` by hash/number → **Alt F is mandatory** for Demo Slice.

## What Fast Finality changes here (2026-08-21)

`run --finality fast` serves reads from the BLS-finalized head, **~2 blocks** behind the
tip instead of ~112. That changes the **depth** column, not the **addressing** column:

- A provider now needs a by-number/by-hash window of **≥3 blocks**, not ≥112. Every row
  that failed only on window depth — BlastAPI (~96), NodeReal (~96), even QuickNode free
  (**5**) — is worth re-probing against this rule before concluding Alt F is mandatory.
- **Tag-only rows are unaffected and still fail the gate.** Confirmed live with
  `bsc-rpc.publicnode.com` under `--finality fast`: the client correctly served
  `safe = tip - 2`, and `eth_getBalance` still returned `-32001` wrapping
  `-32602 distance to target block exceeds maximum proof window` — that endpoint rejects
  by-number proofs at *any* distance, including at the tip. No finality rule fixes that.

Re-probing the paid/keyed rows under the ≥3-block requirement is the next step for this
gate; the numbers in the table above were all measured against the ~112 requirement.

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
