# Local JSON-RPC matrix (wallet mode)

Default bind: `127.0.0.1:8545` (`--allow-non-loopback` required for LAN; no RPC auth in-process). `latest` / `eth_blockNumber` → **Safe** (≥15 distinct subsequent sealers). Fail-closed: no silent passthrough.

| Method | Trust | Notes |
|--------|--------|--------|
| `eth_chainId` | Verified | `0x38` |
| `net_version` | Verified | `56` |
| `net_listening` | Verified | `true` while serving |
| `net_peerCount` | Verified | `0x0` (no P2P; RPC data plane only) |
| `web3_clientVersion` | Verified | `helios-bsc/<version>` |
| `eth_protocolVersion` | Verified | Local `0x41` (not P2P; no upstream) |
| `web3_sha3` | Verified | Local keccak256 of hex bytes (no upstream); payload ≤512 KiB |
| `eth_mining` | Verified | `false` |
| `eth_hashrate` | Verified | `0x0` |
| `eth_accounts` | Verified | `[]` (no unlocked keys) |
| `eth_syncing` | Verified | `false` when Safe exists; object of local verified height otherwise (not upstream tip) |
| `eth_blockNumber` | Verified | Safe height, not tip |
| `eth_getBalance` | Verified | MPT vs local verified `stateRoot` at `n ≤ Safe` (same tags as `eth_getBlockByNumber`: `latest`/`safe`/`finalized` → Safe; hex/hash in-chain and `number ≤ Safe`). EIP-1898 object block ids → `-32602`. Proof window 112 vs requested height. |
| `eth_getTransactionCount` | Verified | Same as balance |
| `eth_getCode` | Verified | Bytecode keccak vs proof `codeHash` at the requested block; ≤24576 bytes (`MaxCodeSize`) |
| `eth_getStorageAt` | Verified | Storage trie vs account `storageHash` at the requested block |
| `eth_getProof` | Verified | EIP-1186 at the requested local header (`n ≤ Safe`); MPT vs that `stateRoot` (account + requested slots). At most **64** storage keys, **32** nodes per account/storage proof, **16 KiB** per node. Keys are hex quantities ≤32 bytes, validated **before** the upstream fetch (junk / non-string / oversize → `-32602`). Response `storageProof` is clipped to the requested keys (empty request → empty array). |
| `eth_call` | Verified (constrained) | Local verified header `n ≤ Safe` (`latest`→Safe). Requires `to` + optional `data`; **no create**, **no state overrides**. Optional EIP-2930 `accessList` is **prefetched** into ProofDb (seed; does not consume `MAX_PROOF_ROUNDS`; ≤32 addresses, ≤64 keys total). Proofs via `eth_getProof` at the requested **hash/number**; execute in **revm**. Unproven SLOAD/account → `-32001` (fail-closed, not zero). `BLOCKHASH` from locally verified headers (`n ≤` executing block in the 256-window); in-window unknown → `-32001`; out-of-window/current → `0` (never `eth_getBlock` from untrusted RPC). Gas cap **50_000_000**; max **8** proof rounds; calldata ≤ **128 KiB**; at most **32** accounts. Revert / Halt → JSON-RPC **code 3** (geth), not `-32001`. Never proxied to upstream `eth_call`. EIP-1898 object block ids → `-32602`. |
| `eth_getBlockByNumber` | Header-verified | At or below Safe; `fullTx=true` → `-32601`. `transactions` is a **hash list** bound to sealed `transactionsRoot` (`ordered_trie_root` of raw tx RLP, geth DeriveSha). Empty root → `[]`. No raw envelopes → hashes omitted (`[]`), not a fake list. Lying raws → `-32001`. Stored sealed header when present; else re-fetch must `Header.Hash()`. |
| `eth_getBlockByHash` | Header-verified | Hash in local chain and `number ≤ Safe`. Same stored-header / Hash() / tx-hash bind. |
| `eth_getUncleCountByBlockNumber` / `ByHash` | Verified | `0x0` at or below Safe (Parlia forbids uncles; checked on every header) |
| `eth_getUncleByBlockNumberAndIndex` / `ByHashAndIndex` | Verified | `null` at or below Safe |
| `eth_coinbase` | Verified | `0x000…0` (no mining) |
| `eth_sendRawTransaction` | Unverified | Broadcast only (always on). Local hex decode + empty/size cap (512 KiB) + **chainId=56** (typed 0x01–0x04 / EIP-155 legacy; unprotected txs rejected). Returned hash is local `keccak256(raw)`; a lying upstream hash is `-32001`. |
| `eth_sendTransaction` / `eth_sign*` / `personal_*` / `debug_*` / `trace_*` / `txpool_*` / `miner_*` / `admin_*` / `engine_*` / `les_*` / `clique_*` / `parlia_*` / `rpc_*` / `bsc_*` | Unsupported | No unlocked keys, no tracing, no consensus RPC (`-32601`) |
| `eth_getTransactionReceipt` | Unverified opt-in | Default `-32601`. `--allow-unverified-passthrough`: header-bound to local Safe (`blockHash` in chain, `number ≤ Safe`). Query hash must be 32 bytes and match `transactionHash`/`hash`. If present: `chainId`=56, `from`/`to`/`contractAddress` 20-byte addresses (`to`/`contractAddress` may be null), `status` ∈ {0,1}, `type` ∈ {0…4}, `gasUsed`/`cumulativeGasUsed` hex quantities, `input`/`data` ≤512 KiB, `logsBloom` 256 bytes if present. Present `logs[]`: 20-byte `address`, ≤4×32-byte topics (≤1024 logs). Logs not MPT-verified (`receiptsRoot` proofs **not implemented**). Pending (null hash+number) allowed if the tx hash still matches. |
| `eth_getTransactionByHash` | Unverified opt-in | Same header-bind + query-hash bind as receipts |
| `eth_getRawTransactionByHash` | Unverified opt-in | Default `-32601`. Flag on: raw hex, `keccak256(raw)` must equal the 32-byte query hash; size cap 512 KiB. Lying payload → `-32001`. |
| `eth_gasPrice` | Unverified opt-in | Default `-32601`. Flag on: hex quantity only (not an object) |
| `eth_maxPriorityFeePerGas` | Unverified opt-in | Same flag as `eth_gasPrice` (EIP-1559 tip). Hex quantity. |
| `eth_feeHistory` | Unverified opt-in | Same flag. JSON object; `oldestBlock` if present is a hex qty of a local verified header number ≤ Safe (`-32602` if not hex, `-32003` if not in chain / above Safe); omit `oldestBlock` keeps array caps only. `baseFeePerGas` / `gasUsedRatio` / `reward` arrays ≤1024; `reward` rows of hex qty if present. |
| `eth_blobBaseFee` | Unverified opt-in | Same flag. Hex quantity. |
| `helios_bsc_syncStatus` | Verified | tip, safe, `lag` / `safeLagBlocks` / `safeLagSeconds`, `safeLagWithinBound`, `unverifiedPassthrough`, `backupTransport`, sealers, proof window, `finality=confirmation-depth`, `sealingSetEnforced`, `proofOk` / `proofFail` / `headersVerified` |
| `helios_bsc_getVerificationStatus` | Verified | same status body (`trustClass`, `finality`, lag fields) |
| `eth_estimateGas` | Verified (constrained, best-effort) | Same policy as `eth_call` (`n ≤ Safe`; `to` + optional `data`; **no create**; **no state overrides**; no `blobVersionedHashes` / `authorizationList`; optional `accessList` prefetch; calldata ≤ **128 KiB**; at most **32** accounts). Never proxied to upstream `eth_estimateGas` / `eth_call`. Unproven SLOAD/account → `-32001`. `BLOCKHASH` from local verified headers (same as `eth_call`). Revert / Halt → JSON-RPC **code 3**. Binary search `TX_GAS..=min(user gas, 50_000_000, block.gasLimit)` (geth/reth; not a single `gas_used`). Max **8** proof rounds for the whole estimate. Gas is **not consensus**. |
| `eth_getLogs` / filters / `eth_subscribe` | Unsupported | `-32601` (no log index, no pub/sub) |
| `eth_getBlockTransactionCount*` / `eth_getTransactionByBlock*AndIndex` | Verified | Same `n ≤ Safe` + `transactionsRoot` bind as `eth_getBlock*`. Count is `0x{len}`. ByIndex returns `{hash, blockHash, blockNumber, transactionIndex}` only (`null` if OOR). `fullTx` still `-32601`. |

Remaining (later; **not done**): `receiptsRoot` proofs on receipts/logs; `eth_getLogs`. `transactionsRoot` hashes in `eth_getBlock*` — **closed** (raw-RLP DeriveSha; omit if no envelopes). `accessList` prefetch is **closed**. Historical `n≤Safe` and the proof-round seed budget are **closed**.

Wallet tags: `latest` / `safe` / `finalized` → Safe. Hex number or 32-byte hash is allowed for verified state and `eth_getBlock*` iff the block is in the local verified chain and `number ≤ Safe`. `pending` and `earliest` are rejected (`-32003`), not genesis. HTTP is **POST-only**; missing Content-Type is allowed (curl); `application/json` / `json-rpc` / `jsonrequest` ok; `text/html` and form-urlencoded → **415**. Loopback binds also require a loopback `Host` (403 otherwise).

Error codes: `-32700` parse error, `-32600` invalid request (including empty batch, batch > 64, missing/`jsonrpc` ≠ `"2.0"`, `id` not string≤128 / integer / null, fractional `id`, non-graphic method name), `-32602` `params` not an array or more than 16 params, `-32001` proof failed (unproven SLOAD/account/`BLOCKHASH`/budget), `3` `execution reverted` / halt (geth; not `-32001`), `-32002` stateRoot, `-32003` not synced / wallet tag, `-32601` unsupported. JSON-RPC **batches** are supported (max 64); notifications (no `id`) are omitted from the batch response; a lone notification is HTTP 204 / JSON `null`.

`--checkpoint` enables sealing-set membership **and** in-turn difficulty. `--oracle` / `helios-bsc soak --min-unique 10` compares MPT balances to an independent host (not the proof upstream). `--backup` / `HELIOS_BSC_BACKUP` is transport failover only (not a trust oracle). Wallet pointing: [wallet-guide.md](./wallet-guide.md).
