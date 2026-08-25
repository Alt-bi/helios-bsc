# helios-bsc status

**Updated:** 2026-08-25 · **Released:** [v0.1.0](https://github.com/Alt-bi/helios-bsc/releases/tag/v0.1.0) (5 platforms, `SHA256SUMS`)

## Where the project is

A trust-minimized Parlia light client serving verified JSON-RPC on `127.0.0.1:8545`.
MVP-1 and MVP-2 are in tree. The ≥24 h differential soak passed **2026-08-24** (24.06 h,
exit 0) and 4 h followed on the shipped build (2871 compared, 0 mismatch). Block tags have
served the BEP-126 BLS-finalized head by default since **2026-08-25**. A nightly soak runs
in CI against live mainnet.

**Not audited.** No third party has reviewed the consensus or proof code.

| | |
|---|---|
| Verified reads | balances, nonces, code, storage, `eth_call`, `eth_estimateGas`, headers, receipts, single-block logs |
| Read head | BLS-finalized, ~2 blocks behind the tip (falls back to ~110 without vote keys) |
| History | ~112 blocks; not an archive node |
| Tests | 427, plus an adversarial in-process lying upstream |
| Chain | BSC mainnet, `chainId` 56, pinned to `bnb-chain/bsc` v1.7.8 |

Start at [docs/quickstart.md](docs/quickstart.md); what is verified is in
[docs/rpc-matrix.md](docs/rpc-matrix.md); how each item below was found and checked is in
[docs/engineering-log.md](docs/engineering-log.md).

## Milestones

| Milestone | State |
|-----------|-------|
| Design (reviewed) | Done → `docs/design.md` |
| PR1 scaffold (workspace, licenses, CI, CLI `info`) | **Done** |
| Phase 0 hardfork pin + appendix | **Done** — `bnb-chain/bsc` **v1.7.8** `cdb7548b5baa…` |
| Phase 0 epoch fixtures | **Done** — epoch 116664000 ±2; live `n=21`, `turnLength=8` |
| extraData codec (PR 3b) | **Done** |
| ECDSA seal verify (PR 4) | **Done** — coinbase + difficulty ∈ {1,2}; in-turn match on snapshot (`--checkpoint`) |
| Epoch activation (PR 5) | **Done** — `minerHistoryCheckLen` (87 @ N=21,T=8); unit-tested |
| Confirmation-depth Safe (PR 6) | **Done** — newest Safe = 15 distinct subsequent sealers; proof window **112** |
| Phase 0 `eth_getProof` matrix | **PASS on the default build.** Measured 2026-08-21, when fast finality was still opt-in; only `--finality confirmation-depth` is a partial pass… [→ detail](docs/engineering-log.md#phase-0-eth_getproof-matrix) |
| MPT `eth_getProof` (PR 8) | **Done** — account trie vs `stateRoot`; WBNB fixture + mutated node reject; **exclusion** (absent account) → empty; **inlined** children (<32 B / nested list) for storage proofs. ≤32 nodes per account/storage proof; `getCode` ≤24576 B. |
| Local JSON-RPC (PR 9) | **Done** — wallet-mode Safe reads + verified `eth_getProof` + `helios_bsc_syncStatus` (`backupTransport`) + wallet meta + `eth_protocolVersion`… [→ detail](docs/engineering-log.md#local-json-rpc-pr-9) |
| Code / storage / broadcast (PR 11) | **Done** — `eth_getCode` (keccak vs proof `codeHash`; WBNB bytecode fixture + lying code reject), `eth_getStorageAt` (storage trie… [→ detail](docs/engineering-log.md#code-storage-broadcast-pr-11) |
| Header-verified `eth_getBlock*` | **Done** — `eth_getBlockByNumber` / `ByHash` at or below Safe; hydrated txs → `-32601`; uncle RPCs `0x0`/`null` (Parlia); `eth_coinbase` zeros. Sealed header stored at ingest — serve/persist without re-fetch; lying re-fetch ignored. |
| Verified state at `n ≤ Safe` | **Done** — `eth_getBalance` / nonce / code / storage / proof / `eth_call` / `estimateGas` at a local verified header with `n ≤ Safe` (same rule as `eth_getBlockB… [→ detail](docs/engineering-log.md#verified-state-at-n-safe) |
| Filters / subscribe | **Done** — `eth_newFilter` / `eth_subscribe` / filter RPCs stay `-32601` (no log index). |
| Parent-linked header walk | **Done** — consecutive numbers + `parentHash` vs previous **computed** hash (including append stitch)… [→ detail](docs/engineering-log.md#parent-linked-header-walk) |
| Adversarial mock (PR 10) | **Done** — `helios-bsc-mock` + `RpcUpstream` trait; `Node::handle` fail-closed on lying seals/proofs/parent/`stateRoot`; 14-sealer ≠ Safe. Unproven `eth_call` SLOAD/account is fail-closed (`-32001`), not zero. |
| Constrained `eth_call` (MVP-2 slice 1) | **Done** — local verified header `n ≤ Safe` (`latest`→Safe); `to` + optional `data`; iterative `eth_getProof` at the requested hash/number; **revm 42**… [→ detail](docs/engineering-log.md#constrained-eth_call-mvp-2-slice-1) |
| Best-effort `eth_estimateGas` (MVP-2 slice 2) | **Done** — same `n ≤ Safe` constraints as `eth_call`; proof-backed revm **binary search** (geth/reth; not Helios raw `gas_used`)… [→ detail](docs/engineering-log.md#best-effort-eth_estimategas-mvp-2-slice-2) |
| Checkpoint / sealing-set (PR 13 slice) | **Done** — `--checkpoint` + persist + multisource + `verify-checkpoint`. Persist is **tmp+rename**. Sealing-set addresses must be unique 20-byte values… [→ detail](docs/engineering-log.md#checkpoint-sealing-set-pr-13-slice) |
| Soak (PR 14) | **Done (code + live ≥10 + 1h re-diff)** — unique recatch/retry; nonce vs oracle when historical nonce exists. Duration soak **re-diffs the full list** after unique is full (`visit_all`… [→ detail](docs/engineering-log.md#soak-pr-14) |
| Bind policy | **Done** — default loopback… [→ detail](docs/engineering-log.md#bind-policy) |
| Data-plane backup | **Done** — `--backup` / `HELIOS_BSC_BACKUP`: transport failover if the primary RPC errors. Both untrusted; seals/MPT still apply. Soak backup must not be the oracle host. |
| Header.Hash() | **Done** — keccak256(RLP(header)) vs RPC `hash` on every sealed header (v1.7.8 `Header.Hash()` / `gen_header_rlp.go`). Re-fetch / persist / checkpoint match the computed hash, not the JSON field. |
| Sync counters | **Done** — `syncStatus.proofOk` / `proofFail` / `headersVerified` (process lifetime). |
| Demo Slice | **Vertical closed:** Safe=15, wallet `latest`→Safe, WBNB MPT, `verify-checkpoint` GATE PASS, soak **19 unique / 214 compared / 0 mismatch** vs BlastAPI over **≥1h** re-diff. Wallet guide: `docs/quickstart.md`. |
| Operator doctor | **Done** — `helios-bsc doctor` prints RPC **hosts** only (no keys); Pasteur countdown; checkpoint age without the sealing-set list. |
| `syncStatus` lag fields | **Done** — `safeLagBlocks` / `safeLagSeconds` + `finality` (`confirmation-depth` at the time; the default became `fast-finality` on 2026-08-25). Demo Slice DoD. |
| Pasteur profile | **LIVE 2026-08-25** — activated at unix `1787625000` (02:30 UTC)… [→ detail](docs/engineering-log.md#pasteur-profile) |
| Checkpoint from epoch extraData | **Done** — `write-checkpoint --sealing-set-from-epoch` (activated extraData only; not miners). |
| Unverified passthrough (opt-in) | **Done** — `--allow-unverified-passthrough`: receipts/txs header-bound to Safe **and** to the requested 32-byte hash… [→ detail](docs/engineering-log.md#unverified-passthrough-opt-in) |
| Operator SLOs | **Done** — `docs/slo.md`; `doctor` slo=ok/warn/fail; `syncStatus.safeLagWithinBound`. |
| Prometheus metrics | **Done** — opt-in `run --metrics` → `GET /metrics` (only non-POST route… [→ detail](docs/engineering-log.md#prometheus-metrics) |
| Bootstrap epoch state | **Done** — a checkpoint carries no `turnLength` and cannot say whether a set switch is pending, so both are read back from the two epoch headers around it… [→ detail](docs/engineering-log.md#bootstrap-epoch-state) |
| **≥ 24h GA soak** | **PASS 2026-08-24** — 24.06 h continuous (2026-08-23 12:02 → 2026-08-24 12:05), exit code 0… [→ detail](docs/engineering-log.md#-24h-ga-soak) |
| 4h soak on the shipped build | **PASS 2026-08-24** — 4 h 01 m uninterrupted on the release build of this branch, with `--state`, blastapi (upstream) vs publicnode (oracle), `--finality fast`… [→ detail](docs/engineering-log.md#4h-soak-on-the-shipped-build) |
| First-run usability | **Done 2026-08-25** — the first command anyone ran demanded an epoch block number the operator had to compute as `floor(block / epochLength) * epochLength`… [→ detail](docs/engineering-log.md#first-run-usability) |
| Release binaries | **Done 2026-08-25** — `release.yml` builds on a `v*` tag for linux-x86_64 (musl, static, plus a glibc build), macOS arm64 and x86_64, and windows-x86_64… [→ detail](docs/engineering-log.md#release-binaries) |
| Bootstrap near the tip | **Fixed 2026-08-25** — `write-checkpoint --block latest` followed by `run` exited with "no Safe head in lookback"… [→ detail](docs/engineering-log.md#bootstrap-near-the-tip) |
| Superseded epoch refused | **Fixed 2026-08-25** — `--sealing-set-from-epoch` accepted any *already activated* epoch, and every epoch below the checkpoint has activated… [→ detail](docs/engineering-log.md#superseded-epoch-refused) |
| EVM fork level | **Fixed 2026-08-25** — the EVM ran at `SpecId::CANCUN` while BSC has been on **Prague since 2025-03-20** and **Osaka since 2026-04-28** (`params/config.go`: `PragueTime=1742… [→ detail](docs/engineering-log.md#evm-fork-level) |
| Checkpoint provenance | **Done 2026-08-25** — loading a checkpoint with no independent source agreeing to it now warns, naming the reason and the two flags that fix it… [→ detail](docs/engineering-log.md#checkpoint-provenance) |
| Soak finality cross-check | **Done** — the `parlia_*` comparison is the only check that tests this client's attestation bookkeeping against geth rather than against itself… [→ detail](docs/engineering-log.md#soak-finality-cross-check) |
| Soak crash resumption | **Done** — state written after every burst and again on the way out of a failed round, instead of once per round with `?` propagating past the save. Verified live: a run killed 75 s in with zero completed rounds left `compared=18 unique=12 checked_finality=1` and a 64 s session on disk. |
| Upstream connection reuse | **Done** — `ureq::post(url)` runs on a use-once `Agent`, so every JSON-RPC call paid a fresh TCP + TLS handshake. Counted through a local forwarder over one walk: **59 requests / 59 connections** before, **55 / 3** after. Reuse is worth ~275 ms per call on publicnode, ~500 ms on bsc-dataseed. |
| Refresh amplification | **Done** — every served method called `refresh()`, which always polled the upstream… [→ detail](docs/engineering-log.md#refresh-amplification) |
| Request panic containment | **Done** — a panic in `serve_one` ended the worker thread, and a panic under the chain lock poisoned it so the rest died on their next request: listener up, `/metrics` green, nobody answering. Handling now runs under `catch_unwind`, answers `-32603`, and bumps `helios_bsc_request_panics_total`. The background poller is wrapped too. |
| In-turn difficulty | **Done** — range on all headers; `inturn_validator` on checkpoint walks (padded fixture sets cannot satisfy live in-turn). |
| SignRecently (Bohr recents) | **Done** — `seenTimes >= turnLength` in `minerHistoryCheckLen`; recents cleared on set switch. Maxwell FF prune applied (see the row below). |
| Unsealed header fields | **Done** — empty uncles, gasUsed/gasLimit, `baseFeePerGas` (see below), Lorentz mixDigest ms, Bohr zero `parentBeaconRoot`, extraData ≤100KiB… [→ detail](docs/engineering-log.md#unsealed-header-fields) |
| Cascading parent fields | **Done** — `MilliTimestamp ≥ parent + BlockInterval` (Ramanujan floor); Lorentz+ gasLimit bound `parent/1024`, min 5000. Fixture 998→999 is exactly 450ms. The out-of-turn refinement of the same floor is the row below. |
| **Out-of-turn backoff** | **Done 2026-08-22** — `blockTimeVerifyForRamanujanFork` is a *verifier* rule (`verifyCascadingFields` calls it)… [→ detail](docs/engineering-log.md#out-of-turn-backoff) |
| Header-verify remaining | **Empty.** `baseFee`, out-of-turn backoff and the Maxwell prune all closed; see their rows. |
| Fixture authenticity | **Done** — `scripts/verify_fixtures.py` re-checks every fixture against live mainnet (headers field-by-field, proof `stateRoot`+`blockHash`, WBNB bytecode). Verified 2026-08-21: all pass. |
| **Fast Finality (BLS)** | **Done (consensus + observability)** — `crates/helios-bsc-consensus/src/vote.rs`: strict canonical-only RLP decode of `VoteAttestation`, `VoteData.Hash()`… [→ detail](docs/engineering-log.md#fast-finality-bls) |
| **Maxwell FF `recents` prune (BEP-524)** | **Done** — implemented from the pinned **v1.7.8** source, not from prose… [→ detail](docs/engineering-log.md#maxwell-ff-recents-prune-bep-524) |
| FF-backed block tags | **Done, now the default (2026-08-25)** — `run` resolves `latest` / `safe` / `finalized` (and the historical-read ceiling) to the BLS-finalized head, ~2 blocks instead of ~110… [→ detail](docs/engineering-log.md#ff-backed-block-tags) |
| FF verified live | **Done 2026-08-21** — ran against mainnet via `bsc-rpc.publicnode.com` from a checkpoint written with `--sealing-set-from-epoch` (21 BLS vote keys). `syncStatus`: `finality=fast-finality`, `finalizedLagBlocks=2` on four consecutive samples, `justifiedLagBlocks=1`, `safeLagBlocks` 108–113 unchanged. `/metrics`: `helios_bsc_finality_mode 1`, `finalized_lag_blocks 2`. |
| Concurrent RPC listener | **Done** — the accept loop was single-threaded, so the lock-free `/metrics` scrape still queued behind one blocked `helios_bsc_syncStatus`… [→ detail](docs/engineering-log.md#concurrent-rpc-listener) |
| Untrusted-input hardening | **Done 2026-08-22** — an audit pass over the paths that parse bytes chosen by someone else… [→ detail](docs/engineering-log.md#untrusted-input-hardening) |
| Sync/state-machine hardening | **Done 2026-08-22** — two state-corruption bugs where a *fail-closed check corrupted state on its way out*… [→ detail](docs/engineering-log.md#syncstate-machine-hardening) |
| BEP-126 checked against geth itself | **Done 2026-08-24** — the attestation path had no direct differential coverage: fixtures, plus the indirect evidence that a walk did not wedge… [→ detail](docs/engineering-log.md#bep-126-checked-against-geth-itself) |
| Soak: resumable, and wider than balances | **Done 2026-08-23** — two separate gaps, both found by actually running the gate… [→ detail](docs/engineering-log.md#soak-resumable-and-wider-than-balances) |
| BEP-126 step-1 range check | **Done 2026-08-22** — auditing the rest of `verifyVoteAttestation` after the ancestor-window bug turned up one check we never had: geth rejects `SourceNumber >= TargetNumbe… [→ detail](docs/engineering-log.md#bep-126-step-1-range-check) |
| Fermi attestation ancestor window | **Done 2026-08-22** — the client enforced the **pre-Fermi** BEP-126 rule on a Fermi chain and **wedged on honest mainnet blocks**… [→ detail](docs/engineering-log.md#fermi-attestation-ancestor-window) |
| Soak gates the head it claims | **Done 2026-08-22** — `soak --finality fast` accepted the flag and then soaked **confirmation depth**… [→ detail](docs/engineering-log.md#soak-gates-the-head-it-claims) |
| Real sealing-set tests | **Done** — `header_116663000.json` is the epoch that *governs* the fixture blocks… [→ detail](docs/engineering-log.md#real-sealing-set-tests) |

## What is next

The MVP-1 and MVP-2 gates are closed and v0.1.0 has shipped. What is open:

1. **No audit.** Nothing here has been reviewed by a third party. This is the single
   largest gap between the current state and anything anyone should hold funds behind.
2. **Log ranges and filters.** `eth_getLogs` serves a single block; a range, `eth_newFilter`
   and `eth_subscribe` stay `-32601`. Ranges need an index this client deliberately does not
   keep, so this is a design question, not a missing function.
3. **Receipt `transactionHash` is not bound to `transactionsRoot`.** Neither are the
   non-consensus receipt fields (`from`, `to`, `gasUsed`, `contractAddress`,
   `effectiveGasPrice`) — they are structurally validated and labelled as such in
   [docs/rpc-matrix.md](docs/rpc-matrix.md), not verified.
4. **The soak needs an oracle serving `parlia_`.** With `--finality fast` the run
   cross-checks its justified/finalized pair against geth's own answer and fails closed if
   that check never produced a verdict. Most public BSC endpoints answer `-32601`;
   `bsc-rpc.publicnode.com` serves it, which is why it is the oracle in CI.
5. **Re-pin when a fork changes a Parlia rule.** `upstream-pin.yml` watches `bnb-chain/bsc`
   weekly and diffs the four files this client transcribes. Pasteur (2026-08-25) changed
   none of them; the pin is still v1.7.8.

## What the mainnet scan showed (2026-08-21) and how each item closed

Sampled **2400 headers** across ~1.8M blocks of history (115.4M → 117.24M, `bsc-dataseed.bnbchain.org`), plus **600 consecutive** at the tip:

| Observed | Count |
|----------|-------|
| `difficulty` = `0x2` (in-turn) | **2400 / 2400** — no out-of-turn block found |
| `baseFeePerGas` = `0x0` | **2400 / 2400** |
| `gasLimit` = `0x3473bc0` | **2400 / 2400** (never moved) |
| MilliTimestamp gap | **exactly 450 ms**, 599 / 599 consecutive pairs |

What this means for each item:

- **Out-of-turn backoff** — **closed 2026-08-22.** The scan is why it stayed open: it only constrains `difficulty == 1` headers and found none, so no fixture can exercise it against real data, and a check invented from prose would fire first during a validator outage — i.e. break the client exactly when out-of-turn blocks finally appear. What changed is that it was *not* invented from prose: the pinned v1.7.8 `ramanujanfork.go` / `parlia.go` are readable, and the only unreproducible input (a Go `math/rand` shuffle) turns out to be a **non-negative additive term** that a sound floor can simply drop. Every remaining unknown is an explicit no-op branch, so the outage failure mode above is structurally impossible: with no trustworthy sealing set or an incompletely walked `recents` window the rule does not run at all. Synthetic-walk tests cover both sides of every gate; the five live fixtures are all in-turn and are asserted **unaffected**.
- **EIP-1559 `baseFee`** — **closed 2026-08-22**, and the scan was right that "the Ethereum formula is not the rule here". The source says so outright: `CalcBaseFee` opens with `if config.IsInBSC() { return InitialBaseFeeForBSC }`, `IsInBSC()` is `c.Parlia != nil`, and `InitialBaseFeeForBSC` is `0`. There is no parent-dependent formula on BSC to port — `VerifyEIP1559Header` reduces to *present after London, absent before, and equal to zero*, which is what `seal.rs::verify_base_fee` enforces. **This is not a new defence against a lying RPC** and is not claimed as one: `baseFeePerGas` is inside `EncodeSigHeader`, so a restated value already breaks the seal. It buys a precise error instead of a signature mismatch, and it makes our verifier surface match geth's exactly.
- **Maxwell FF recents prune** — **closed** earlier, same way: nine lines of readable Go in the pinned `v1.7.8` `consensus/parlia/snapshot.go`, implemented from source and cited. Unit-tested in `snapshot.rs` on both sides of the fork gate.

General point, unchanged: all three are *protocol well-formedness* rules the sealing set already enforces, and all three fields are seal-protected (`live_epoch_set_rejects_restated_difficulty_via_seal`). Against a lying **RPC** they add nothing. They bind a malicious **validator**, which already requires 15-of-21 collusion — outside the stated trust model. They were low-priority hardening, and they are now done; the GA blocker was never these.
### Other items the scan closed

- `eth_estimateGas` best-effort — **closed** (proof-backed binary search; MethodPolicy Verified; never proxied). Local `BLOCKHASH` — **closed**. Revert/Halt JSON-RPC **code 3** — **closed** (geth; not `-32001`).
- Fast Finality BLS — **implemented and verified** (see the row above). The Maxwell FF `recents` prune that it unblocked is now **done** (its own row above). That follow-up — serving the block tags from BLS finality — **shipped 2026-08-25** as the default, gated on the ≥24 h soak that passed the day before. Note the prune's companion fix made `finalized()` **lag correctly**: it now only advances on two consecutive justified blocks, per `updateAttestation`, so anything reading it moves slightly later than before. Because BLS finality lands **2 blocks** behind the tip instead of 106–112, the `eth_getProof` provider window stops being the binding constraint it is in [docs/proof-provider-matrix.md](docs/proof-provider-matrix.md) — but only once the tag actually resolves there.
- `receiptsRoot` RPC proofs on mined receipts/logs; `eth_getLogs` — **closed** (`bin/helios-bsc/src/rpc_server.rs`: untrusted receipt JSON re-encoded to consensus RLP and bound to the sealed `receiptsRoot` via `verify_receipt_list`; `eth_getLogs` is single-block only — `fromBlock==toBlock` or `blockHash` — adversarial-tested against omitted/lying logs). `transactionsRoot` hashes in `eth_getBlock*` — **closed** (raw-RLP DeriveSha; empty root or no envelopes → `[]`; lying list → `-32001`). Count/ByIndex **Verified**. Opt-in `eth_getRawTransactionByHash` — **closed** (keccak-bound). `accessList` prefetch — **closed**. Historical `n≤Safe` — **closed**. **Superseded 2026-08-25.** This entry recommended pinning `SpecId::CANCUN`; that recommendation was wrong, because BSC had been on Prague since 2025-03-20 and Osaka since 2026-04-28, so the client was executing under rules the chain had left. The spec is now derived from the executing block's timestamp — see *EVM fork level* in [docs/engineering-log.md](docs/engineering-log.md), including the EIP-7702 hypothesis that the live test disproved.

## Live pins (do not assume design-doc 16)

| Param | Value |
|-------|------:|
| epochLength | 1000 |
| turnLength | **8** |
| N_seal | 21 |
| minerHistoryCheckLen | 87 |
| proof window | 112 |
| Safe lag | ~106–112 live / 120 in-turn upper |
