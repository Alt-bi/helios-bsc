# Threat model (implemented)

Wallet RPC treats the upstream as an **untrusted data plane**. Integrity comes from Parlia seals + MPT proofs against a Safe `stateRoot`. Light-client security is **at most** BSC sealing-set security.

| Threat | What we do |
|--------|------------|
| Lying balance / nonce / code / storage | `eth_getProof` vs Safe `stateRoot`; claimed fields must match trie; bytecode keccak vs `codeHash` |
| Lying / unverified `eth_call` | **Verified-or-error**, never passthrough and never proxied to upstream `eth_call`. Safe only (`latest`→Safe); `to` + optional `data`; revm on iterative `eth_getProof` at Safe hash/number. No state overrides; no create. Calldata ≤ **128 KiB**; at most **32** accounts; gas cap **50_000_000**; max **8** proof rounds. Revert and Halt currently share RPC `-32001` with proof failure (wallets cannot distinguish). |
| Lying / unverified `eth_estimateGas` | **Verified-or-error**, never passthrough and never proxied to upstream `eth_estimateGas` / `eth_call`. Same Safe-only constraints as `eth_call` (including 128 KiB / 32-account caps). Binary-search estimate is **best-effort** (gas is not consensus). |
| Unproven `eth_call` SLOAD / account | Fail-closed `-32001` (**not** zero / empty). Missing proof is not empty storage. `BLOCKHASH` is currently fail-closed `Missing`/`-32001` (always). |
| Valid proof for the wrong root | Bind to consensus-verified `stateRoot` (`-32002` / `-32001`) |
| Mutated trie node | MPT walker rejects; CI adversarial tests |
| Disconnected / reordered headers | Consecutive numbers + `parentHash`; append stitches to the existing tip |
| Deep reorg / eclipse window | Lookback-only resync after a link break must share a hash with the local chain within **21** blocks of the old tip (`max_reorg_depth = N_seal`). Deeper → fail-closed (`--checkpoint`). Checkpoint replay from the trusted origin is unchanged. |
| Lying JSON `hash` field | Recompute geth `Header.Hash()` = keccak256(RLP(header)); reject mismatch. Re-fetch of `eth_getBlock*` / persist must Hash() to the local verified hash |
| Lying re-fetch after ingest | Sealed `RpcBlockHeader` is stored on the verified chain; `eth_getBlock*` and checkpoint persist prefer that copy |
| Unauthorized sealer (valid ECDSA, not in set) | Only with `--checkpoint`; lookback-only does **not** check membership (`sealingSetEnforced=false`). Use `--require-checkpoint`. |
| Bogus difficulty | Every header: difficulty ∈ `{1,2}`. With `--checkpoint`: must match in-turn (`offset = (parent+1)/turnLength % N`). |
| Structural header lies | Empty uncle hash; `gasUsed ≤ gasLimit ≤ 2^63-1`; Lorentz mixDigest milliseconds (`MilliTimestamp/1000 == time`); Bohr+ `parentBeaconRoot` is the zero hash; extraData ≤ 100KiB; Cancun `withdrawalsRoot` is the empty trie; `header.Time` more than 15s in the future; Parlia nonce is 8 zero bytes. |
| Too-soon / gas-limit jump | Parent `MilliTimestamp + BlockInterval` floor (Ramanujan; out-of-turn backoff not applied). Lorentz+ `|Δ gasLimit| < parent/1024` and `gasLimit ≥ 5000`. |
| Repeat sealer spam | `--checkpoint`: Bohr `SignRecently` (`seenTimes >= turnLength` in the 87-block window). Recents start empty at the checkpoint. Maxwell prune-to-FF is **not** applied (no BLS). |
| Malicious checkpoint | Age ≤24h; `verify-checkpoint`; `--require-multisource-checkpoint` on a **different host** (two Ankr keys count as one source). Persist is write-tmp + rename (no truncated JSON). Sealing-set addresses must be unique 20-byte values; `hash` / `parentHash` / `stateRoot` must be 32 bytes |
| Epoch extraData rewrite | Epoch extraData must parse (n≥1 **unique** validator records, Bohr `turnLength` in 1..=64). Activation still waits `minerHistoryCheckLen` (87 @ N=21,T=8). Lookback-only still does **not** check membership |
| 100/110-block “Safe” | Not used. Safe = **15** distinct subsequent sealers (`floor(2N/3)+1`) |
| Tag-only `eth_getProof` | Proofs by Safe **hash then number**, never `latest` on the upstream |
| Silent passthrough | Unsupported methods `-32601`. `eth_call` / `eth_estimateGas` are verified-or-error (never silent, never upstream `eth_call` / `eth_estimateGas`). Receipts/gasPrice stay `-32601` unless `--allow-unverified-passthrough`. |
| Lying receipt / tx object | Opt-in only; `blockHash` must be in the local verified chain and `number ≤ Safe`. Query hash must match `transactionHash`/`hash` (no swap of another mined tx). Present `chainId` must be 56; address fields 20 bytes; `status` ∈ {0,1}; `type` ∈ {0…4}. Present `logs[]`: each log has a 20-byte `address`, ≤4 topics of 32 bytes; log `transactionHash` if set must match; log `blockHash` if set must match the receipt. Logs are **not** MPT-verified (no receiptsRoot proof) |
| Fee-oracle junk | Opt-in `eth_gasPrice` / tip / blob base fee must be a hex quantity; `eth_feeHistory` must be an object |
| `eth_sendRawTransaction` drop / MEV | Labeled unverified broadcast; garbage/empty/oversized hex is rejected locally. **chainId must be 56** (no unprotected legacy). Wallet hash is local keccak256(raw); mismatch vs upstream is fail-closed |
| Signing / unlocked-account RPC | `eth_sign*`, `eth_sendTransaction`, `personal_*` stay `-32601` (no keys in-process). Also `debug_`/`trace_`/`txpool_`/`engine_`/`les_`/`parlia_`/`bsc_`/`rpc_`/`clique_` |
| Proof window too shallow | Fail-closed if Safe lag > 112; soak skips that round, does not invent a balance |
| Primary RPC down / rate-limit | Optional `--backup` retries the same call on a second URL. Backup is **not** a trust oracle; results still fail-closed on seal/MPT |
| Bind on LAN | Default `127.0.0.1:8545`. Non-loopback refused unless `--allow-non-loopback` (no in-process auth) |
| DNS rebinding to loopback | Loopback bind requires HTTP `Host` in `127/8` / `localhost` / `::1` (403 otherwise). No `Access-Control-Allow-Origin` |

What we **do not** claim: Fast Finality BLS (MVP-2), or privacy against the upstream seeing queried addresses.
