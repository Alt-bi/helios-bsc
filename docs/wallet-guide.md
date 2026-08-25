# Wallet / integrator short guide

Point a wallet or `cast`/`ethers` at the local process. Default bind is loopback only.

```bash
helios-bsc run --upstream "$HELIOS_BSC_UPSTREAM" --listen 127.0.0.1:8545
# optional: --checkpoint checkpoint.json --require-checkpoint
```

Custom RPC URL: `http://127.0.0.1:8545` · chainId **56**.

## Tags (wallet mode)

| What the client asks | What helios-bsc serves |
|----------------------|------------------------|
| `latest` / `eth_blockNumber` | **Safe** — newest block with ≥15 distinct subsequent sealers |
| `safe` / `finalized` | Same head as `latest`. Since 2026-08-25 that is the **BLS-finalized** head (~2 blocks) when the client has BLS vote keys, else the confirmation-depth Safe head; `run --finality confirmation-depth` pins the latter. `helios_bsc_syncStatus.safeSource` says which |
| Exact number/hash | Local verified header with `n ≤ Safe` (same as `eth_getBlockByNumber`; `latest` still maps to Safe) |

Safe lag on mainnet is ~106–112 blocks (~50s), not “the last mined block”.

**Fast Finality (BEP-126).** The client verifies the BLS vote attestation in each sealed header and tracks a justified and a finalized head, measured **2 blocks** behind the tip on live mainnet — the observed norm over 120 consecutive headers in a healthy period, not a guaranteed bound. Since 2026-08-25 it is **served by default**: `latest` / `safe` / `finalized` resolve to the BLS-finalized head, falling back to the confirmation-depth Safe head whenever no finalized head is known, and `run --finality confirmation-depth` pins the older rule. The startup line names the rule actually in force, so an unarmed client reading at ~110 blocks says why. A wallet on the default reads `helios_bsc_syncStatus` → `finality` (`fast-finality` vs `confirmation-depth`), `finalizedBlock` / `finalizedHash`, `finalizedLagBlocks`, `justifiedBlock` / `justifiedLagBlocks`, and `finalityHead` (the verified head the lags are measured against). The fields are `null` and `finality` stays `confirmation-depth` until the client has BLS vote keys — write the checkpoint with `write-checkpoint --sealing-set-from-epoch` to carry them; it never guesses a key. Details: `docs/fast-finality.md`.

## Methods

**Verified** (MPT vs Safe `stateRoot`, or local header): `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`, `eth_getProof` (Safe only; ≤64 storage keys; 20-byte address), constrained `eth_call` (Safe only; `to` + optional `data`; revm + iterative `eth_getProof` at Safe hash/number; unproven SLOAD/account → `-32001`; `BLOCKHASH` from local verified headers, in-window unknown → `-32001`, out-of-window/current → `0`; gas cap 50_000_000; max 8 proof rounds; calldata ≤128 KiB; at most 32 accounts; Revert and Halt use JSON-RPC **code 3** (geth), not `-32001`; no state overrides; no create), best-effort `eth_estimateGas` (same proof-backed path and constraints as `eth_call`; geth/reth binary search, not a single `gas_used`; max 8 proof rounds; **gas is not consensus**; unproven → `-32001`; never proxied), `eth_chainId`, `eth_blockNumber`, `eth_getBlockByNumber` / `ByHash` (header only; `fullTx=true` → `-32601`; hash is geth `Header.Hash()`). Uncle RPCs are `0x0` / `null` (Parlia). Local (no upstream): `web3_sha3`, `eth_mining`=`false`, `eth_hashrate`=`0x0`, `eth_coinbase`=`0x000…0`. JSON-RPC over HTTP is POST-only (1 MiB body cap). Loopback binds also require a loopback `Host` header (no CORS `*`).

**Unverified broadcast (always on):** `eth_sendRawTransaction`. Local checks: hex, empty/512 KiB cap, **chainId 56** (typed 0x01–0x04 or EIP-155; no unprotected txs). The returned hash is local `keccak256(raw)`, not the upstream’s word.

**Unverified opt-in** (`run --allow-unverified-passthrough`): receipts / tx-by-hash **header-bound to Safe** and to the requested 32-byte hash; `eth_gasPrice` / `eth_maxPriorityFeePerGas` / `eth_blobBaseFee` hex quantities; `eth_feeHistory` object (`oldestBlock` if present is a local verified header ≤ Safe). Default is `-32601`.

**`eth_getLogs` is supported for a single block only** — `fromBlock == toBlock`, or `blockHash`; a range is `-32602`. Logs come from receipts bound to the sealed `receiptsRoot`, never from an upstream `eth_getLogs`.

**Unsupported (no index / no keys / later):** log **ranges**, filters, `eth_subscribe`, `eth_sendTransaction`, `eth_sign*`, `personal_*`, `debug_*`, `txpool_*`. Fast Finality **is** implemented and verified, but exposes **no new RPC method** — it adds fields to `helios_bsc_syncStatus` and changes which head the existing tags resolve to (see Tags above).

There is **no silent passthrough**. Unsupported or unverified-without-flag methods hard-error.

## Proof window

Verified reads need `eth_getProof` at Safe (by **number**, then hash). Free Ankr is ~108–112 blocks and ~3 proofs/burst. If `helios_bsc_syncStatus.inProofWindow` is false or balances return `-32001`, swap to a deeper RPC — do not lower the 15-sealer rule.

`helios_bsc_syncStatus` / `helios_bsc_getVerificationStatus` expose tip, Safe, lag, and `finality` — `confirmation-depth`, or `fast-finality` once a valid BLS attestation has been verified, alongside the `finalized*` / `justified*` fields above. `finality` describes what the client has **verified**, not which head the tags serve — that stays the confirmation-depth Safe head unless you pass `--finality fast`.
