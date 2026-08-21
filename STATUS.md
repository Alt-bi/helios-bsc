# helios-bsc status

**Updated:** 2026-08-21

| Milestone | State |
|-----------|--------|
| Design (reviewed) | Done → `docs/design.md` |
| PR1 scaffold (workspace, licenses, CI, CLI `info`) | **Done** |
| Phase 0 hardfork pin + appendix | **Done** — `bnb-chain/bsc` **v1.7.8** `cdb7548b5baa…` |
| Phase 0 epoch fixtures | **Done** — epoch 116664000 ±2; live `n=21`, `turnLength=8` |
| extraData codec (PR 3b) | **Done** |
| ECDSA seal verify (PR 4) | **Done** — coinbase + difficulty ∈ {1,2}; in-turn match on snapshot (`--checkpoint`) |
| Epoch activation (PR 5) | **Done** — `minerHistoryCheckLen` (87 @ N=21,T=8); unit-tested |
| Confirmation-depth Safe (PR 6) | **Done** — newest Safe = 15 distinct subsequent sealers; proof window **112** |
| Phase 0 `eth_getProof` matrix | **Ankr number proofs ~≤108** (hash often `not supported`). Live Safe lag **106–112**. Catch-up after header walk required (45s walk ages Safe out of window). Fail-closed if lag > window. |
| MPT `eth_getProof` (PR 8) | **Done** — account trie vs `stateRoot`; WBNB fixture + mutated node reject; **exclusion** (absent account) → empty; **inlined** children (<32 B / nested list) for storage proofs. ≤32 nodes per account/storage proof; `getCode` ≤24576 B. |
| Local JSON-RPC (PR 9) | **Done** — wallet-mode Safe reads + verified `eth_getProof` + `helios_bsc_syncStatus` (`backupTransport`) + wallet meta + `eth_protocolVersion`. JSON-RPC 2.0 **batch ≤64** / method name ≤64 ASCII graphic / `id` string≤128 or integer (no fractions) / **params ≤16** / parse `-32700` / invalid `-32600` / `"jsonrpc":"2.0"` / lone notification → `null`. Extra namespaces `les_`/`parlia_`/`bsc_`/`rpc_`/`clique_` stay `-32601`. |
| Code / storage / broadcast (PR 11) | **Done** — `eth_getCode` (keccak vs proof `codeHash`; WBNB bytecode fixture + lying code reject), `eth_getStorageAt` (storage trie; WBNB slot-0 fixture + lying value reject), unverified `eth_sendRawTransaction` (hex/empty/512KiB + **chainId=56** + local keccak hash bind). Signing/`personal_*`/`debug_*`/`txpool_*` stay `-32601`. |
| Header-verified `eth_getBlock*` | **Done** — `eth_getBlockByNumber` / `ByHash` at or below Safe; hydrated txs → `-32601`; uncle RPCs `0x0`/`null` (Parlia); `eth_coinbase` zeros. Sealed header stored at ingest — serve/persist without re-fetch; lying re-fetch ignored. |
| Verified state at `n ≤ Safe` | **Done** — `eth_getBalance` / nonce / code / storage / proof / `eth_call` / `estimateGas` at a local verified header with `n ≤ Safe` (same rule as `eth_getBlockByNumber`). `latest` still maps to Safe. Proofs/code at the **requested** hash/number; `stateRoot` from that `VerifiedBlock`. Proof window 112 vs requested height (fail-closed). EIP-1898 object block ids → `-32602`. |
| Filters / subscribe | **Done** — `eth_newFilter` / `eth_subscribe` / filter RPCs stay `-32601` (no log index). |
| Parent-linked header walk | **Done** — consecutive numbers + `parentHash` vs previous **computed** hash (including append stitch). `catch_up` resyncs lookback after a parent mismatch **only if** the new window overlaps the old chain within **21** blocks (`max_reorg_depth = N_seal`). Deeper reorg → fail-closed. |
| Adversarial mock (PR 10) | **Done** — `helios-bsc-mock` + `RpcUpstream` trait; `Node::handle` fail-closed on lying seals/proofs/parent/`stateRoot`; 14-sealer ≠ Safe. Unproven `eth_call` SLOAD/account is fail-closed (`-32001`), not zero. |
| Constrained `eth_call` (MVP-2 slice 1) | **Done** — local verified header `n ≤ Safe` (`latest`→Safe); `to` + optional `data`; iterative `eth_getProof` at the requested hash/number; **revm 19.7**; unproven SLOAD/account → `-32001`; gas cap **50_000_000**; max **8** proof rounds; no state overrides; no create; never proxy upstream `eth_call`. `BLOCKHASH` from locally verified headers (in-window unknown → `-32001`, not zero; out-of-window/current → `0`). WBNB `totalSupply` + `name`(slot0) fixtures. Fast Finality is **not** this slice. |
| Best-effort `eth_estimateGas` (MVP-2 slice 2) | **Done** — same `n ≤ Safe` constraints as `eth_call`; proof-backed revm **binary search** (geth/reth; not Helios raw `gas_used`); `TX_GAS..=min(user, 50M, block.gasLimit)`; max **8** proof rounds for the whole estimate. Unproven SLOAD/account → `-32001`. Never proxy upstream `eth_estimateGas` / `eth_call`. MethodPolicy **Verified**. Gas is **not consensus** (best-effort). Fast Finality is **not** this slice. |
| Checkpoint / sealing-set (PR 13 slice) | **Done** — `--checkpoint` + persist + multisource + `verify-checkpoint`. Persist is **tmp+rename**. Sealing-set addresses must be unique 20-byte values; hash/parentHash/stateRoot 32 bytes. `--max-sync` 16000 (~2h) for restart from last-verified. Lookback 130 is the no-checkpoint Safe window only. Reorg/link-break resyncs lookback or replays the origin checkpoint. |
| Soak (PR 14) | **Done (code + live ≥10 + 1h re-diff)** — unique recatch/retry; nonce vs oracle when historical nonce exists. Duration soak **re-diffs the full list** after unique is full (`visit_all`; re-matches are not empty bursts). Live 2026-08-19 Ankr vs BlastAPI: smoke **unique=10**; idle 1h **unique=19 / compared=19**; re-diff 1h **GATE PASS unique=19 compared=214 match=214 mismatch=0 skip=38** (13 rounds; Ankr window skips, not mismatches). |
| Bind policy | **Done** — default loopback; `--allow-non-loopback` for LAN (warns: no in-process auth). Docker: `Dockerfile` + `compose.yaml` publish **127.0.0.1:8545** only (`docs/deploy.md`). JSON-RPC HTTP is **POST-only**, body capped at 1 MiB. Loopback `Host` required (403 on DNS-rebinding Host); no CORS `*`. Content-Type missing/JSON ok; `text/html` / form → **415**. |
| Data-plane backup | **Done** — `--backup` / `HELIOS_BSC_BACKUP`: transport failover if the primary RPC errors. Both untrusted; seals/MPT still apply. Soak backup must not be the oracle host. |
| Header.Hash() | **Done** — keccak256(RLP(header)) vs RPC `hash` on every sealed header (v1.7.8 `Header.Hash()` / `gen_header_rlp.go`). Re-fetch / persist / checkpoint match the computed hash, not the JSON field. |
| Sync counters | **Done** — `syncStatus.proofOk` / `proofFail` / `headersVerified` (process lifetime). |
| Demo Slice | **Vertical closed:** Safe=15, wallet `latest`→Safe, WBNB MPT, `verify-checkpoint` GATE PASS, soak **19 unique / 214 compared / 0 mismatch** vs BlastAPI over **≥1h** re-diff. Wallet guide: `docs/wallet-guide.md`. |
| Operator doctor | **Done** — `helios-bsc doctor` prints RPC **hosts** only (no keys); Pasteur countdown; checkpoint age without the sealing-set list. |
| `syncStatus` lag fields | **Done** — `safeLagBlocks` / `safeLagSeconds` + `finality=confirmation-depth` (Demo Slice DoD). |
| Pasteur profile | **Named, not live** — `params_at` names `pasteur` at unix `1787625000` (2026-08-25); extraData/epoch/turnLength unchanged vs Fermi until re-pin. |
| Checkpoint from epoch extraData | **Done** — `write-checkpoint --sealing-set-from-epoch` (activated extraData only; not miners). |
| Unverified passthrough (opt-in) | **Done** — `--allow-unverified-passthrough`: receipts/txs header-bound to Safe **and** to the requested 32-byte hash; `chainId`=56, address fields including `contractAddress`, `status` ∈ {0,1}, structural `logs[]`, `input`/`data` ≤512 KiB, `logsBloom` 256 B. Fee oracles: hex qty / feeHistory object (arrays ≤1024). Default still `-32601`. `eth_getProof` ≤64 storage keys (hex ≤32 B, validated before fetch); served fields overwritten from the verified account. Account methods reject non-20-byte addresses locally. `pending`/`earliest` rejected. |
| Operator SLOs | **Done** — `docs/slo.md`; `doctor` slo=ok/warn/fail; `syncStatus.safeLagWithinBound`. |
| In-turn difficulty | **Done** — range on all headers; `inturn_validator` on checkpoint walks (padded fixture sets cannot satisfy live in-turn). |
| SignRecently (Bohr recents) | **Done** — `seenTimes >= turnLength` in `minerHistoryCheckLen`; recents cleared on set switch. No Maxwell FF prune. |
| Unsealed header fields | **Done** — empty uncles, gasUsed/gasLimit, Lorentz mixDigest ms, Bohr zero `parentBeaconRoot`, extraData ≤100KiB, empty `withdrawalsRoot`, `header.Time ≤ now+15s`, Parlia nonce empty. Epoch extraData must parse (n≥1 **unique** validators, Bohr `turnLength` 1..=64); membership still needs `--checkpoint`. |
| Cascading parent fields | **Done** — `MilliTimestamp ≥ parent + BlockInterval` (Ramanujan floor, no out-of-turn backoff); Lorentz+ gasLimit bound `parent/1024`, min 5000. Fixture 998→999 is exactly 450ms. |
| Header-verify remaining | **Not implemented** (no fixtures; do not claim done): **out-of-turn backoff**, **Maxwell FF recents prune**, **EIP-1559 parent `baseFee` formulas**. |

## Next engineering steps

1. **≥24h** mainnet differential soak, mismatch=0 — still the **MVP-1 GA live gate**. 1h re-diff 2026-08-19 is closed (Ankr vs BlastAPI: unique=19, compared=214, match=214, mismatch=0, skip=38 Ankr window, not false-accept). **Not claimed done.**
2. Re-pin after Pasteur (**2026-08-25**, scheduled, **not live**) if extraData / epoch / turnLength change.
3. Remaining header-verify items that still lack fixtures: **out-of-turn backoff**, **Maxwell FF recents prune**, **EIP-1559 parent `baseFee` formulas**. Not implemented — do not invent from prose.
4. `eth_estimateGas` best-effort — **closed** (proof-backed binary search; MethodPolicy Verified; never proxied). Local `BLOCKHASH` — **closed**. Revert/Halt JSON-RPC **code 3** — **closed** (geth; not `-32001`).
5. Fast Finality BLS — **not implemented**; later. Deeper RPC (≥128) still helps if proofs start failing.
6. Optional remaining (later; **not done**): historical `n≤Safe` state reads; proof-round seed budget; `receiptsRoot`; `transactionsRoot` hashes.

## Live pins (do not assume design-doc 16)

| Param | Value |
|-------|------:|
| epochLength | 1000 |
| turnLength | **8** |
| N_seal | 21 |
| minerHistoryCheckLen | 87 |
| proof window | 112 |
| Safe lag | ~106–112 live / 120 in-turn upper |
