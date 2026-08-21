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
| `safe` / `finalized` | Same Safe head (MVP-1; Fast Finality not verified) |
| Exact number/hash | Only if it is the current Safe |

Safe lag on mainnet is ~106–112 blocks (~50s), not “the last mined block”.

## Methods

**Verified** (MPT vs Safe `stateRoot`, or local header): `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`, `eth_getProof` (Safe only; ≤64 storage keys; 20-byte address), constrained `eth_call` (Safe only; `to` + optional `data`; revm + iterative `eth_getProof` at Safe hash/number; unproven SLOAD/account → `-32001`; gas cap 50_000_000; max 8 proof rounds; calldata ≤128 KiB; at most 32 accounts; `BLOCKHASH` currently fail-closed `Missing`/`-32001` always; Revert and Halt currently share RPC `-32001` with proof failure so wallets cannot distinguish; no state overrides; no create), best-effort `eth_estimateGas` (same proof-backed path and constraints as `eth_call`; geth/reth binary search, not a single `gas_used`; max 8 proof rounds; **gas is not consensus**; unproven → `-32001`; never proxied), `eth_chainId`, `eth_blockNumber`, `eth_getBlockByNumber` / `ByHash` (header only; `fullTx=true` → `-32601`; hash is geth `Header.Hash()`). Uncle RPCs are `0x0` / `null` (Parlia). Local (no upstream): `web3_sha3`, `eth_mining`=`false`, `eth_hashrate`=`0x0`, `eth_coinbase`=`0x000…0`. JSON-RPC over HTTP is POST-only (1 MiB body cap). Loopback binds also require a loopback `Host` header (no CORS `*`).

**Unverified broadcast (always on):** `eth_sendRawTransaction`. Local checks: hex, empty/512 KiB cap, **chainId 56** (typed 0x01–0x04 or EIP-155; no unprotected txs). The returned hash is local `keccak256(raw)`, not the upstream’s word.

**Unverified opt-in** (`run --allow-unverified-passthrough`): receipts / tx-by-hash **header-bound to Safe** and to the requested 32-byte hash; `eth_gasPrice` / `eth_maxPriorityFeePerGas` / `eth_blobBaseFee` hex quantities; `eth_feeHistory` object. Default is `-32601`.

**Unsupported (no index / no keys / later):** `eth_getLogs`, filters, `eth_subscribe`, `eth_sendTransaction`, `eth_sign*`, `personal_*`, `debug_*`, `txpool_*`. Fast Finality is **not** implemented.

There is **no silent passthrough**. Unsupported or unverified-without-flag methods hard-error.

## Proof window

Verified reads need `eth_getProof` at Safe (by **number**, then hash). Free Ankr is ~108–112 blocks and ~3 proofs/burst. If `helios_bsc_syncStatus.inProofWindow` is false or balances return `-32001`, swap to a deeper RPC — do not lower the 15-sealer rule.

`helios_bsc_syncStatus` / `helios_bsc_getVerificationStatus` expose tip, Safe, lag, and `finality=confirmation-depth`.
