# Engineering log

How each non-obvious item was found, closed and checked. This is the maintainer's record;
for the current state of the project see [STATUS.md](../STATUS.md), and for what the client
does today [quickstart.md](quickstart.md).

Every entry states what was wrong, what changed, and what was measured afterwards. Where a
hypothesis turned out to be wrong, it says so rather than being dropped.

## Consensus and header verification

### Parent-linked header walk

**Done** — consecutive numbers + `parentHash` vs previous **computed** hash (including append stitch). `catch_up` resyncs lookback after a parent mismatch **only if** the new window overlaps the old chain within **21** blocks (`max_reorg_depth = N_seal`). Deeper reorg → fail-closed.

### Pasteur profile

**LIVE 2026-08-25** — activated at unix `1787625000` (02:30 UTC). The pin already contained it and `IsPasteur` appears in no `consensus/parlia/*.go` file, so no client change was needed and none was made. Confirmed on the live chain the same morning: `doctor` reports `live_fork: pasteur`, a checkpoint at 117956350 writes `forkId=pasteur` with vote keys, and a soak run entirely on post-Pasteur blocks matched an independent oracle **116/116, 0 mismatch, 4 parlia cross-checks, lag 2**.

### Bootstrap epoch state

**Done** — a checkpoint carries no `turnLength` and cannot say whether a set switch is pending, so both are read back from the two epoch headers around it. `turnLength` is seeded from the chain (the fork table's 8 is a guess; v1.7.8 `parlia.go` anticipates 16 and every fixture here is 8, so nothing would have noticed). A checkpoint inside an epoch's activation window — 87 blocks in 1000 — is **refused** at both `write-checkpoint` and walk time rather than seeded, because adopting the announced set would mean taking a future sealing set from an unverified header. Verified live 2026-08-24 against `bsc-dataseed`: block `E+40` refused with the activation height and a usable alternative, `E-1` accepted with `turnLength=8` read from epoch `117814000`.

### Unsealed header fields

**Done** — empty uncles, gasUsed/gasLimit, `baseFeePerGas` (see below), Lorentz mixDigest ms, Bohr zero `parentBeaconRoot`, extraData ≤100KiB, empty `withdrawalsRoot`, `header.Time ≤ now+15s`, Parlia nonce empty. Epoch extraData must parse (n≥1 **unique** validators, Bohr `turnLength` 1..=64); membership still needs `--checkpoint`.

### **Out-of-turn backoff**

**Done 2026-08-22** — `blockTimeVerifyForRamanujanFork` is a *verifier* rule (`verifyCascadingFields` calls it), so a `diffNoTurn` header could previously arrive up to 2 s early and we took it. geth's `backOffTime` adds `backOffSteps[idx]*wiggleTime` from a Go `math/rand` shuffle that cannot be reproduced — so `seal.rs::verify_out_of_turn_backoff` enforces `delay` alone, dropping a term that is non-negative by construction: a strict **under**-estimate, so every header geth accepts, this accepts. `backOffTime` has four `0` returns; `verifyCascadingFields` has already excluded three by the time this runs (in-turn sealer, recently-signed sealer, sealer not in set), and the fourth needs `delay` zeroed, which only the in-turn validator having signed recently can do — gated explicitly. Every unknown (no sealing set, padded set, no walked parent millisecond, `countRecents` window not fully walked) makes the check a **no-op**, because a missing `recents` entry lowers a count and could otherwise demand *more* than geth does.

### Real sealing-set tests

**Done** — `header_116663000.json` is the epoch that *governs* the fixture blocks, so `LightEngine` tests run with the genuine 21-validator set and `enforce_inturn` **on** (padded sets could not reach that path). In-turn offset `(parent+1)/turnLength % N` confirmed against **40/40** live blocks.

## Fast finality (BEP-126)

### **Fast Finality (BLS)**

**Done (consensus + observability)** — `crates/helios-bsc-consensus/src/vote.rs`: strict canonical-only RLP decode of `VoteAttestation`, `VoteData.Hash()`, aggregate BLS verify via `blst` (min_pk, G1 key 48 B / G2 sig 96 B, DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`), bitset → **sorted** validator mapping, quorum `ceil(2N/3)` = **14 of 21** (*not* the confirmation-depth 15). Verifies the **real** signatures on all five mainnet fixture headers. Linkage in `snapshot.rs`: target must be the direct parent, source must be the justified block, set taken at `TargetNumber-1` (differs from the current set only on an activation block, so one generation of history is kept). A present-but-invalid attestation **rejects the header**; an absent one never does. Vote keys ride in the checkpoint (`write-checkpoint --sealing-set-from-epoch`) and survive restart; without them the client stays confirmation-depth and never guesses. Live mainnet: finalized lag **2 blocks** vs 106–112 (`scripts/verify_attestations.py`, 120/120 headers). See [docs/fast-finality.md](fast-finality.md). **Not** done: serving the `finalized` tag from BLS finality.

### **Maxwell FF `recents` prune (BEP-524)**

**Done** — implemented from the pinned **v1.7.8** source, not from prose. `consensus/parlia/snapshot.go` `apply`, immediately after `snap.Recents[number] = validator`: `if chainConfig.IsMaxwell(header.Number, header.Time) { latestFinalizedBlockNumber := snap.getFinalizedNumber(); for blockNumber := range snap.Recents { if blockNumber <= latestFinalizedBlockNumber { delete(snap.Recents, blockNumber) } } }`, with `getFinalizedNumber()` = `s.Attestation.SourceNumber` or **0**. In `snapshot.rs`: `prune_recents_to_finalized`, gated `time >= MAXWELL_TIME` on the applied header. **No-op without a finalized head** — `getFinalizedNumber()` is 0 and `recents` never holds block 0, so the confirmation-depth path is untouched; the Bohr epoch sentinel is keyed `u64::MAX - epoch` and survives. Required a matching fix to attestation adoption: `updateAttestation` advances **only the target** when `SourceNumber+1 != TargetNumber`, so finality moves only on two consecutive justified blocks — replacing the source wholesale (the previous behaviour) would report a finalized block ahead of geth's and prune history geth still counts, which is the fail-open direction. Maxwell is **live** on mainnet (activated 2025-06-30), so this rule is in force today, not dormant.

### FF-backed block tags

**Done, now the default (2026-08-25)** — `run` resolves `latest` / `safe` / `finalized` (and the historical-read ceiling) to the BLS-finalized head, ~2 blocks instead of ~110; `--finality confirmation-depth` pins the old rule. The ≥24h soak that gated this passed 2026-08-24. Used **only** when the finalized head is newer than confirmation depth *and* names a block in the local verified chain, so the flip can never move reads backwards or onto a block taken on an upstream's word. Without BLS vote keys there is no finalized head and reads stay at confirmation depth — the deeper, safer answer, and the startup line now **says so and why** instead of leaving the operator to infer it from a lag gauge. `syncStatus` separates the two: `finalityMode` is what was asked for, `finality` / `safeSource` are what is in force; `distinctSealers` / `requiredSealers` keep describing confirmation depth. Verified live on the post-Pasteur chain: armed → `safe == finalizedBlock`, `safeSource=fast-finality`, lag **2**; unarmed → `finality=confirmation-depth`, lag **106**, with the reason printed.

### BEP-126 checked against geth itself

**Done 2026-08-24** — the attestation path had no direct differential coverage: fixtures, plus the indirect evidence that a walk did not wedge. Both bugs found in it this week (the Fermi ancestor window, the missing `source < target` rule) came from walking mainnet, not from the suite. BSC exposes its own RPC namespace — the pinned `internal/web3ext/web3ext.go` registers `admin, debug, dev, eth, miner, net, parlia, rpc, txpool`, and **no** `bsc_`/`bnb_` prefix exists anywhere — whose `parlia_getJustifiedNumber` / `parlia_getFinalizedNumber` are defined in `consensus/parlia/api.go` as `snapshot(at that header).Attestation.TargetNumber` and `.SourceNumber`: word for word what `Snapshot::justified` / `Snapshot::finalized` return. Both take a **named block**, so the comparison is an exact equality rather than a race between two moving tips. Guarded against the one thing that could fake a disagreement: the oracle's hash at that height is confirmed to be our block first, so a reorg on either side is a skip, not a mismatch. Run **once per round**, not per address — few providers expose `parlia` and those that do throttle (`bsc-dataseed.bnbchain.org` answers `-32601`, blastapi refuses anything outside core EVM, `bsc-rpc.publicnode.com` serves it). Verified live: local `justified 117809641 finalized 117809640` against geth's identical answer at the same block.

### BEP-126 step-1 range check

**Done 2026-08-22** — auditing the rest of `verifyVoteAttestation` after the ancestor-window bug turned up one check we never had: geth rejects `SourceNumber >= TargetNumber` **before it consults the chain at all**. Ours only compared the source against the justified block, and that comparison is *silent* right after a checkpoint when nothing is justified yet — precisely the window geth's unconditional check exists to cover. Finality is defined by `source < target`; a pair that violates it describes nothing. Added as `VoteData::source_below_target`, called first in `check_attestation` in geth's order. The rest of the audit came back clean: extra ≤ 256, popcount ≤ N, quorum `CeilDiv(2N,3)`, `KeyValidate` per key and `FastAggregateVerify` over `VoteData.Hash()` all match. One divergence is left **deliberately**: a bitset bit above the validator count is refused here where geth ignores it. That is documented at `voted_indices` — honest sealers index within the set, so it is not reachable from honest block production, unlike the ancestor-window rule which honest mainnet hits routinely.

### Fermi attestation ancestor window

**Done 2026-08-22** — the client enforced the **pre-Fermi** BEP-126 rule on a Fermi chain and **wedged on honest mainnet blocks**. `check_attestation` required `TargetNumber == parent`; v1.7.8 `verifyVoteAttestation` step 3 instead walks `GetAncestorGenerationDepth(header)` generations back from the parent looking for the target, and that depth is `1` only **before Fermi** — from Fermi on it is `kAncestorGenerationDepth = 3`. Found by the 24h soak, not by a test: the run died on header **117425792**, whose attestation targets **117425789** with parent **117425791**. Because the walk is sequential and the snapshot cannot skip a header, every later round retried the same block and failed — the soak spent its whole life printing one error. Fixed by resolving the target against a 3-deep ancestor ring the snapshot now keeps (geth reads these from its database; a light client keeps only what it can be asked about), and `attestation_set` is now keyed on `TargetNumber - 1` as geth's step 4 specifies rather than on `number - 2`, which were the same value only while the target was the parent. A target inside the window whose block this snapshot has not walked — possible for the first two generations after a checkpoint — is **not adopted** rather than accepted on the upstream's word or treated as a violation. Three regression tests, one of them carrying the exact live numbers. Note what hid this: all five live fixtures and every synthetic walk happen to have `target == parent`, so 394 passing tests said nothing. **Diagnostics**: the soak's retry path printed `{e}`, showing only `snapshot 0x6ffc680` and hiding the cause — now `{e:#}`.

## Execution: eth_call and eth_estimateGas

### Constrained `eth_call` (MVP-2 slice 1)

**Done** — local verified header `n ≤ Safe` (`latest`→Safe); `to` + optional `data`; iterative `eth_getProof` at the requested hash/number; **revm 42**; unproven SLOAD/account → `-32001`; gas cap `min(user, 50_000_000, block gasLimit)`, and from Osaka also EIP-7825's **16,777,216**, which is the one that binds live; max **8** proof rounds; no state overrides; no create; never proxy upstream `eth_call`. **Chain precompiles the local EVM lacks → `-32001`.** *(Superseded 2026-08-25 — see [EVM fork level](#evm-fork-level).)* The EVM then ran at a fixed `SpecId::CANCUN`, implementing only `0x01..=0x0a`, so BLS12-381 at `0x0b..=0x11` was refused although BSC has run it since Prague. The spec now follows the executing block's timestamp and the boundary is derived from revm's table, leaving refused: `0x0100` `p256Verify` and BSC's own `0x64` `tmHeaderValidate` / `0x65` `iavlMerkleProofValidatePlato` / `0x66` `blsSignatureVerify` / `0x67` `cometBFTLightBlockValidateHertz` / `0x68` `verifyDoubleSignEvidence` / `0x69` `secp256k1SignatureRecover`. Those used to fall through as ordinary accounts — whose proof verifies as *empty* — so a `CALL` succeeded and returned nothing. Refused instead. `BLOCKHASH` from locally verified headers (in-window unknown → `-32001`, not zero; out-of-window/current → `0`). WBNB `totalSupply` + `name`(slot0) fixtures. Fast Finality is **not** this slice.

### Best-effort `eth_estimateGas` (MVP-2 slice 2)

**Done** — same `n ≤ Safe` constraints as `eth_call`; proof-backed revm **binary search** (geth/reth; not Helios raw `gas_used`); `TX_GAS..=` the same cap as `eth_call` (from Osaka, EIP-7825's 16,777,216); max **8** proof rounds for the whole estimate. Unproven SLOAD/account → `-32001`. Never proxy upstream `eth_estimateGas` / `eth_call`. MethodPolicy **Verified**. Gas is **not consensus** (best-effort). Fast Finality is **not** this slice.

### EVM fork level

**Fixed 2026-08-25** — the EVM ran at `SpecId::CANCUN` while BSC has been on **Prague since 2025-03-20** and **Osaka since 2026-04-28** (`params/config.go`: `PragueTime=1742436600`, `OsakaTime=1777343400`). Executing at the wrong fork is not a refusal, it is a wrong number. `eth_estimateGas` came back **low** and drifted further with calldata — 25407 vs geth's 31513 at 1000 zero bytes, a 24% shortfall — because EIP-7623's calldata floor arrived in Prague. Low is the dangerous direction: a wallet trusting it sends a transaction that runs out of gas and pays for it. The spec is now chosen from the executing block's own timestamp, so historical reads run under the rules that applied to them. After: 31160 vs 31513, and ours is exactly `21000 + 10*tokens`; the ~1% left is geth's own `ErrorRatio` (1.5% "allowed overestimation ratio for faster estimation termination"), not our error. Two consequences fell out: **BLS12-381 precompiles `0x0b..=0x11`** are implemented from Prague and are no longer refused — the classifier now asks revm rather than carrying a second copy of the boundary — and **EIP-7825** is enforced (`MaxTxGas = 1<<24`), where our 50M call cap sat 3× above what BSC accepts. `eth_call` output verified identical to geth on live mainnet. EIP-7702 was checked too and needed nothing: revm resolves `0xef01` delegation at the bytecode layer, confirmed against a live delegated EOA.

## Checkpoints

### Checkpoint / sealing-set (PR 13 slice)

**Done** — `--checkpoint` + persist + multisource + `verify-checkpoint`. Persist is **tmp+rename**. Sealing-set addresses must be unique 20-byte values; hash/parentHash/stateRoot 32 bytes. `--max-sync` 16000 (~2h) for restart from last-verified. Lookback 130 is the no-checkpoint Safe window only. Reorg/link-break resyncs lookback or replays the origin checkpoint.

### Superseded epoch refused

**Fixed 2026-08-25** — `--sealing-set-from-epoch` accepted any *already activated* epoch, and every epoch below the checkpoint has activated. Passing one that a later epoch had superseded wrote a checkpoint with a stale sealing set, which then failed at run time as `difficulty 2 does not match in-turn (want 1)` — a message that says nothing about the actual mistake. `write-checkpoint` already computes the epoch in force for its activation-window check, so it now cross-checks the operator's choice against it. Found by making the mistake while testing something else.

### Checkpoint provenance

**Done 2026-08-25** — loading a checkpoint with no independent source agreeing to it now warns, naming the reason and the two flags that fix it. Everything this client verifies is verified *relative to* the checkpoint — the sealing set comes from it and every later header is checked against that set — so one taken from a lying provider is a self-consistent fake chain, not one bad answer. `checkpoint_policy` already warned when there was **no** checkpoint; this is the symmetric case, and it was the one thing the client never mentioned. Not made fatal by default: the client cannot invent a second endpoint, and breaking every existing invocation to say something a warning says is the wrong trade. The nightly CI soak runs the strict path instead — three independent hosts with `--require-multisource-checkpoint`.

## The RPC surface

### Local JSON-RPC (PR 9)

**Done** — wallet-mode Safe reads + verified `eth_getProof` + `helios_bsc_syncStatus` (`backupTransport`) + wallet meta + `eth_protocolVersion`. JSON-RPC 2.0 **batch ≤64** / method name ≤64 ASCII graphic / `id` string≤128 or integer (no fractions) / **params ≤16** / parse `-32700` / invalid `-32600` / `"jsonrpc":"2.0"` / lone notification → `null`. Extra namespaces `les_`/`parlia_`/`bsc_`/`rpc_`/`clique_` stay `-32601`.

### Code / storage / broadcast (PR 11)

**Done** — `eth_getCode` (keccak vs proof `codeHash`; WBNB bytecode fixture + lying code reject), `eth_getStorageAt` (storage trie; WBNB slot-0 fixture + lying value reject), unverified `eth_sendRawTransaction` (hex/empty/512KiB + **chainId=56** + local keccak hash bind). Signing/`personal_*`/`debug_*`/`txpool_*` stay `-32601`.

### Verified state at `n ≤ Safe`

**Done** — `eth_getBalance` / nonce / code / storage / proof / `eth_call` / `estimateGas` at a local verified header with `n ≤ Safe` (same rule as `eth_getBlockByNumber`). `latest` still maps to Safe. Proofs/code at the **requested** hash/number; `stateRoot` from that `VerifiedBlock`. Proof window 112 vs requested height (fail-closed). EIP-1898 object block ids → `-32602`.

### Unverified passthrough (opt-in)

**Done** — `--allow-unverified-passthrough`: receipts/txs header-bound to Safe **and** to the requested 32-byte hash; `chainId`=56, address fields including `contractAddress`, `status` ∈ {0,1}, structural `logs[]`, `input`/`data` ≤512 KiB, `logsBloom` 256 B. Fee oracles: hex qty / feeHistory object (arrays ≤1024; `oldestBlock` if present is a local verified header ≤ Safe). Default still `-32601`. `eth_getProof` ≤64 storage keys (hex ≤32 B, validated before fetch); served fields overwritten from the verified account. Account methods reject non-20-byte addresses locally. `pending`/`earliest` rejected.

## Hardening

### Untrusted-input hardening

**Done 2026-08-22** — an audit pass over the paths that parse bytes chosen by someone else. **RLP**: `decode_one` recursed once per nested list with no bound, so a ~200 KiB `eth_sendRawTransaction` body of nested empty lists — under `MAX_RAW_TX` — overflowed the stack and *aborted the process* (not a catchable panic); depth now capped at 32. Same decoder accepted three non-canonical spellings geth rejects with `ErrCanonSize` (`0x81 xx` for a byte < 0x80, long form under 56 bytes, leading-zero length prefixes) — two encodings of one value means two hashes. **Proofs**: `retain_requested_storage` kept every entry matching a requested slot while only the first is verified, so a second entry with a forged `value` rode out unchecked; `storageProof[]` is now capped at 64 (verification is quadratic in a length the RPC chooses) and over-long keys can no longer alias a real slot through `pad32`. **Receipts**: `logs[]` was echoed verbatim although `receiptsRoot` binds only `address`/`topics`/`data`, so `logs[0].blockHash` / `blockNumber` / `transactionHash` / `logIndex` could name another block through a *verified* method — now rebuilt from consensus values plus the local header, sharing `eth_getLogs`' block-wide index; `from`/`to`/`contractAddress`/`gasUsed`/`effectiveGasPrice` are structurally checked as `rpc-matrix.md` already promised. **Tx binding**: "proven empty block" and "upstream served no envelopes" were the same empty vector, so counts answered `0x0` and by-index answered `null` for blocks that certainly have transactions; the unproven case now fails closed. **`eth_call`**: executing block and BLOCKHASH window were resolved under two separate lock acquisitions — a reorg between them ran an old-chain block against new-chain ancestors. **Transport**: `into_json` reads through ureq's unbounded `into_reader()`; capped at 64 MiB, and header batches now require exactly the requested JSON-RPC `id` set instead of defaulting a missing id to 0. **MPT leaves**: `decode_storage_leaf` fell back to `raw.to_vec()` on any decode failure and `decode_account` took a balance of any width — both then reached `pad32`, which keeps the *low* 32 bytes, so a malformed leaf became a plausible value instead of an error. **Hex-prefix**: only flags 0..=3 exist per the Yellow Paper, and geth's `compactToHex` never validates — it infers leaf-ness from the terminator nibble, so for flag 4 or 5 it reads a **leaf** where masking `flag & 2` here read an **extension**. Refused outright rather than picking a side of a divergence on a byte that cannot occur; the even-length padding nibble must also be zero. **Slot keys**: `decode_slot_key` and `verify_storage_slot` still folded over-long keys through `pad32`, the same aliasing already fixed in `retain_requested_storage`. Everything in this last group is hash-bound to a root from a sealed header, so none of it is reachable from a lying upstream and none is claimed as a security fix — “cannot happen” is a reason to error, not to guess. **Verified live 2026-08-22** after the whole pass: 130-header walk plus a 156-header checkpoint walk (sealing set + BLS attestations), then `soak --once --min-unique 10` — **compared=10 match=10 mismatch=0 skip=0** against an independent oracle, so real trie nodes and leaves still decode.

### Sync/state-machine hardening

**Done 2026-08-22** — two state-corruption bugs where a *fail-closed check corrupted state on its way out*. **Apply ordering**: `LightEngine::apply_header` and `append_new_with_snapshot` both ran `snapshot.apply_header` (which mutates) *before* `verify_cascading_vs_parent`. A header passing every snapshot check but failing the Ramanujan floor or the gasLimit bound advanced the snapshot while `chain` stayed put; from then on `apply_verified`'s parent-link check compared against a hash the chain never recorded, so **every later header failed too** — one bad block wedged the client until restart. Reaching it needs a valid seal on a rule-violating header, i.e. a dishonest validator, which is inside the threat model: reject the block, keep running. Cascading now runs first; `cascading_rejection_leaves_snapshot_and_chain_in_step` was confirmed to **fail** against the old ordering (snapshot 116663999 vs chain 116663998) before being kept. **Checkpoint durability**: `atomic_write` did `remove_file` then `rename`, giving away the one property temp-then-rename exists for — between the two the checkpoint did not exist, so a crash or a failed rename left the operator with **no** trust anchor rather than a stale one. `std::fs::rename` replaces an existing file on Windows too (std uses `MoveFileExW` + `MOVEFILE_REPLACE_EXISTING`; probed on this platform), so the remove bought nothing. Now `File::create` + `write_all` + **`sync_all`** then rename, with the temp cleaned up on either failure. Verified live 2026-08-22 after both: 157-header checkpoint walk (sealing set + BLS), `GATE: PASS`, 2/2 vs an independent oracle.

## Soak and the GA gates

### Soak (PR 14)

**Done (code + live ≥10 + 1h re-diff)** — unique recatch/retry; nonce vs oracle when historical nonce exists. Duration soak **re-diffs the full list** after unique is full (`visit_all`; re-matches are not empty bursts). Live 2026-08-19 Ankr vs BlastAPI: smoke **unique=10**; idle 1h **unique=19 / compared=19**; re-diff 1h **GATE PASS unique=19 compared=214 match=214 mismatch=0 skip=38** (13 rounds; Ankr window skips, not mismatches).

### **≥ 24h GA soak**

**PASS 2026-08-24** — 24.06 h continuous (2026-08-23 12:02 → 2026-08-24 12:05), exit code 0. Every gate check in `soak()` is a `bail!` and `main` returns `Result`, so a zero exit is `GATE: PASS` and nothing else. Run with `--finality fast` against blastapi (upstream) / publicnode (oracle). Directly observed at the 17 h 42 m mark: `compared=6271 mismatch=0 skip=1`. **The closing `# SUMMARY` / `# CHECKED` lines were not retained by the runner and the run carried no `--state` file, so the final counts are not on record — the exit code and the duration are.** Build: 2026-08-23, between PR #9 (`7c58b0b`) and PR #10 (`3802259`). It therefore did **not** exercise the `parlia_*` finality cross-check (landed in `3802259`, after that build) nor any 2026-08-24 fix; under the current rules `--finality fast` with `parlia_finality=0` fails closed, so this run would not re-pass unchanged. Re-run on the shipped build: see the row below.

### 4h soak on the shipped build

**PASS 2026-08-24** — 4 h 01 m uninterrupted on the release build of this branch, with `--state`, blastapi (upstream) vs publicnode (oracle), `--finality fast`. `compared=2871 match=2871 mismatch=0 skip=4 unique=19/19 at_fast_head=2772`; sub-checks `balance=1881 nonce=1881 slot0=1881 eth_call=891 parlia_finality=99`. `2772 + 99 = 2871`, i.e. every account and `eth_call` comparison ran at the BLS-finalized head and the 99 finality cross-checks are the remainder — the tally closes exactly. Shorter than 24 h and does not replace it; what it adds is the coverage the 24 h run could not have: 99 independent confirmations that this client's justified/finalized pair matches geth's, plus the first exercise of the bootstrap, transport and refresh changes. Full log and state file retained this time.

### Soak finality cross-check

**Done** — the `parlia_*` comparison is the only check that tests this client's attestation bookkeeping against geth rather than against itself. It used to mark the round done before knowing whether it had run, so a round that started before the first attestation, or hit an oracle blip, silently got no sample and the summary printed `parlia_finality=0` beside `GATE: PASS`. Now set by a verdict, retried up to 3 times per round, and `--finality fast` fails closed when no verdict was ever produced. Requires an oracle serving the `parlia_` namespace (most public BSC endpoints answer `-32601`; `bsc-rpc.publicnode.com` serves it). Verified live 2026-08-24: local `justified 117816765 / finalized 117816764` = geth's.

### Soak: resumable, and wider than balances

**Done 2026-08-23** — two separate gaps, both found by actually running the gate. **(1) The clock reset on a crash.** A soak host died at hour 13.9 and again at 3.1, each time zeroing a 24h gate. `--state <PATH>` now carries totals, unique addresses, the at-fast-head count and the session list through the checkpoint's own temp-then-`sync_all`-then-rename path. Soak time is the **sum of sessions**, never `now - first_start`, and the summary prints the session count and the largest gap — `# SOAKED 6m 05s over 2 session(s) largest_gap=12s` — so a 24h claim always carries the shape of its 24h. A state file from a different upstream, oracle, finality mode or address list is an **error**, not a silent fresh start; an older state version is refused rather than migrated. The clock starts *after* the catch-up walk, which was a real bug: walking a stale checkpoint forward ate the whole budget of a short run and recorded a session in which nothing was compared. **(2) The diff was balances and nonces only.** Both live in the *account* trie, so the **storage** trie and the **EVM** had no live differential coverage whatsoever — `verify_storage_slot`, `decode_storage_leaf`, the hex-prefix and slot-aliasing fixes, and every `eth_call` were tested against mocks and nothing else. Added: **slot 0** for every address, riding on the `eth_getProof` the balance already costs (no extra upstream request), and **`totalSupply()`** through `eth_call_verified` for the ERC-20s, compared byte-for-byte against the oracle. Both are best-effort in one direction only — a provider that ignores `storageKeys` skips the slot instead of losing the balance check with it, while an entry that *is* present and fails to verify stays fatal. Best-effort is also silent, which is how `--finality fast` came to gate a head it never reached, so every OK line names what it reached (`OK [balance,nonce,slot0]`) and the summary tallies it: `# CHECKED balance=4 nonce=4 slot0=4 eth_call=4`. A column stuck at zero means that oracle never served it. Verified live: WBNB slot 0 is the packed `name` string ("Wrapped BNB"), and all four `totalSupply()` answers matched an independent host byte for byte.

### Soak gates the head it claims

**Done 2026-08-22** — `soak --finality fast` accepted the flag and then soaked **confirmation depth**. `fast_finality_head` returns the confirmation-depth head whenever the snapshot carries no usable attestation, and without `--checkpoint` there is no snapshot at all — so a run printed `GATE: PASS` at `lag=108` having never touched BEP-126 finality. The fallback direction is right (never read fresher than verified); the silence is the defect, because this is the **GA gate** and it was certifying the wrong head. Three changes: the run **refuses** `--finality fast` without vote keys instead of downgrading; every burst prints `head=fast|conf` derived the same way the RPC server publishes `read_head_is_fast`, so a per-round fallback is visible rather than averaged away; and the summary carries `at_fast_head=N` with a final **fail-closed** check that `N > 0`. Verified live 2026-08-22 both ways: without a checkpoint it now errors, and with a 21-vote-key checkpoint (`write-checkpoint --sealing-set-from-epoch 0x6ffbf80`) it ran `lag=2  head=fast`, `compared=4 match=4 mismatch=0 at_fast_head=4`.

## Providers and proofs

### Phase 0 `eth_getProof` matrix

**PASS on the default build (2026-08-21 measurements; fast finality became the default 2026-08-25).** Only `--finality confirmation-depth` is a partial pass. BLS finality moves the head to `tip-2`, so the required by-number/by-hash window drops from ~112 blocks to **~3** — which the **free, keyless** `bsc-mainnet.public.blastapi.io` clears (OK at lag 0/2/3/5/8/16/32/64; fails by 96). End-to-end on it: verified `eth_getBalance` / `eth_getStorageAt` / `eth_call`, and **8 addresses vs two independent oracles — 8 match, 0 mismatch**. So **Alt F is no longer mandatory** and no paid key is needed, *if* the operator opts in. Default confirmation depth still needs ~112: Ankr number proofs ~≤108, hash often `not supported`, catch-up required. Tag-only providers (publicnode) fail at **any** lag including the tip — finality changes the required depth, not whether a provider can address a block. Rate-limited probes (`bsc-dataseed`) are inconclusive, not a verdict.

## Operations and release

### Bind policy

**Done** — default loopback; `--allow-non-loopback` for LAN (warns: no in-process auth). Docker: `Dockerfile` + `compose.yaml` publish **127.0.0.1:8545** only (`docs/deploy.md`). JSON-RPC HTTP is **POST-only**, body capped at 1 MiB. Loopback `Host` required (403 on DNS-rebinding Host); no CORS `*`. Content-Type missing/JSON ok; `text/html` / form → **415**.

### Prometheus metrics

**Done** — opt-in `run --metrics` → `GET /metrics` (only non-POST route; loopback `Host` check still applies). All design-doc metrics except `helios_bsc_sync_lag_blocks` (deliberately not implemented — the client has no view of "the network tip" independent of the upstream it is already asking, so it would restate `tip_block`), plus tip/safe/passthrough gauges and the three fast-finality gauges. Scrape is **lock-free and does no network I/O** (gauges published to atomics after each sync) — an earlier build took the chain mutex and a live scrape **hung 180 s** behind a serial header walk; `metrics_do_not_take_the_chain_lock` guards it. Unknown reports `-1`, never `0`. Verified live 2026-08-21: scrape ~2 ms, `safe_lag=106` blocks / 47 s.

### First-run usability

**Done 2026-08-25** — the first command anyone ran demanded an epoch block number the operator had to compute as `floor(block / epochLength) * epochLength`. Naming it added no trust (the header came from the same upstream either way) and made it easy to name a *superseded* epoch; it is derived from `--block` now. `write-checkpoint` also takes `--checkpoint-oracle`, so the second source confirms the checkpoint at the moment it is created rather than after — a checkpoint two hosts disagree on is never written. Setup is three commands: [docs/quickstart.md](quickstart.md).

### Release binaries

**Done 2026-08-25** — `release.yml` builds on a `v*` tag for linux-x86_64 (musl, static, plus a glibc build), macOS arm64 and x86_64, and windows-x86_64; smoke-tests each with `info`; publishes with `SHA256SUMS`. Only first-party actions and the `gh` CLI, and `contents: write` scoped to the publish job alone — a project whose argument is "do not trust what you have not checked" should not ship through actions it has not read. Until this existed, using it meant cloning the repository and installing Rust.

### Bootstrap near the tip

**Fixed 2026-08-25** — `write-checkpoint --block latest` followed by `run` exited with "no Safe head in lookback". Confirmation depth names no head until ~112 blocks of distinct sealers sit behind the tip, so the most natural first command produced a checkpoint the client refused to start from, with no hint that waiting was the entire fix. Bootstrap now extends the walk (bounded at 180 s) and says what it is waiting for. The threshold is unchanged — this is a wait, not a weakening. Verified live: checkpoint at `latest` now comes up serving at lag 2.

### Refresh amplification

**Done** — every served method called `refresh()`, which always polled the upstream, so one 64-element batch (inside `MAX_RPC_BATCH`) fired 64 upstream calls and each serialised behind the chain lock. `refresh` now reuses the last published sync within one block interval — not a staleness budget: the chain cannot produce anything new inside it. `eth_blockNumber` also moved out of the locks, and the published head is read back off the chain. 20 sequential `eth_getBalance` against a live server: **153 upstream calls / 5880 ms each → 55 / 1709 ms**.

### Concurrent RPC listener

**Done** — the accept loop was single-threaded, so the lock-free `/metrics` scrape still queued behind one blocked `helios_bsc_syncStatus`; the existing regression test could not catch it because it calls `metrics_text()` directly. Now 4 worker threads share the `Server`. Live against a non-batching upstream: scrape **100 ms** while a concurrent syncStatus was **90 s** in. Also fixes a pre-existing checkpoint-persist race (fixed `path.tmp` name, two writers) with a unique temp name plus a persist lock.
