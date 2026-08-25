# Fast Finality (BEP-126) for a light client

Normative source: `bnb-chain/bsc` **v1.7.8** — `core/types/vote.go`,
`consensus/parlia/parlia.go` (`getVoteAttestationFromHeader`, `verifyVoteAttestation`,
`GetJustifiedNumberAndHash`, `GetFinalizedHeader`), `consensus/parlia/snapshot.go`.

Companion docs: [consensus-appendix.md](./consensus-appendix.md) (extraData codec, seals),
[checkpointing.md](./checkpointing.md) (root of trust), [design.md](./design.md).

## Why this matters more here than on a full node

`helios-bsc` currently derives a **Safe** head from confirmation depth: the newest block
with ≥ `floor(2*21/3)+1` = **15 distinct subsequent sealers**, measured live at **106–112
blocks** behind the tip (~47–50 s). Two costs follow from that number:

1. **Staleness.** A wallet reading `latest` sees state ~50 s old.
2. **The `eth_getProof` window.** Every verified read needs a proof at the Safe
   `stateRoot`, i.e. ~112 blocks behind the tip. Most public BSC endpoints prune state
   before that — the whole reason [proof-provider-matrix.md](./proof-provider-matrix.md)
   ends in a partial pass. A finality signal that lands a few blocks behind the tip
   makes the provider-window problem largely disappear.

Fast Finality gives exactly that: a BLS aggregate signature from ≥ ⅔ of the validator
set, carried **inside the sealed header**, naming a justified and a finalized block.

## Wire format

A vote attestation rides in `extraData`, between the validator records and the 65-byte
ECDSA seal. `crates/helios-bsc-config/src/extra.rs` already isolates it as
`ParsedExtra::attestation` (raw RLP, possibly empty):

| Block | extraData layout |
|-------|------------------|
| non-epoch | `vanity[32]` · **attestation RLP** · `seal[65]` |
| epoch (Bohr) | `vanity[32]` · `n:u8` · `n × (addr[20] ‖ voteKey[48])` · `turnLength:u8` · **attestation RLP** · `seal[65]` |

The attestation is a 4-item RLP list (`core/types/vote.go`):

```text
VoteAttestation = [ VoteAddressSet : uint64          -- validator bitset
                    AggSignature   : bytes[96]       -- BLS12-381 G2, compressed
                    Data           : VoteData
                    Extra          : bytes ]         -- ≤ 256 bytes

VoteData        = [ SourceNumber : uint64
                    SourceHash   : bytes[32]
                    TargetNumber : uint64
                    TargetHash   : bytes[32] ]
```

The signed message is `keccak256(RLP(VoteData))` — geth's `rlpHash` of the `VoteData`
struct, i.e. the 4-item list above, **not** the enclosing attestation.

BLS parameters are the Ethereum-2 proof-of-possession suite (BSC signs via
prysm → `blst`):

| Parameter | Value |
|-----------|-------|
| Curve | BLS12-381, **min-pubkey-size** (`min_pk`) |
| Public key | 48 bytes, compressed **G1** |
| Signature | 96 bytes, compressed **G2** |
| DST | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` |

## Verification rules

An attestation is optional — a header without one is valid, so its absence must never
fail a header. When one **is** present, all of the following must hold:

1. `Data` is present, and `len(Extra) ≤ 256`.
2. **Target is the direct parent**: `TargetNumber == header.number - 1` and
   `TargetHash == header.parentHash`.
3. **Source is the currently justified block**: `SourceNumber` / `SourceHash` equal the
   justified pair carried by the parent's snapshot. This is what chains attestations
   together and is the reason justification advances one block at a time.
4. `popcount(VoteAddressSet) ≤ N`, where `N` is the size of the active validator set.
5. The voters are `validators[i]` for each set bit `i`, where `validators` is the
   Parlia snapshot set **sorted by address**. The ordering is consensus-critical: a
   different order silently selects different public keys and the signature check then
   fails for the wrong reason.
6. `popcount ≥ ceil(2N/3)` — **14 of 21** on mainnet today. Note this is `ceil(2N/3)`,
   not the confirmation-depth threshold `floor(2N/3)+1` = 15. The two rules are
   different and both are correct in their own context; do not unify them.
7. The aggregate of those public keys verifies `AggSignature` over
   `keccak256(RLP(VoteData))` (`FastAggregateVerify`).

### Which validator set

geth evaluates the bitset against the snapshot at **`TargetNumber - 1`**, i.e. two
blocks below the header being verified. That only differs from "the set at the parent"
in the single block where an epoch set activates (`epochBlock + minerHistoryCheckLen`,
= +87 on mainnet). The light client therefore keeps the previous set and the block at
which the set last changed, and selects the older one when the change is too recent.
Getting this wrong produces a signature failure exactly once per epoch — rare enough to
survive a short test run and be caught only in production.

## Justified and finalized

```text
justified = latest valid attestation's (TargetNumber, TargetHash)
finalized = that same attestation's (SourceNumber, SourceHash)
```

`GetFinalizedHeader` returns the **source** of the snapshot's newest attestation, so
finality trails justification by one justified block. With one attestation per block,
the finalized head sits a small constant number of blocks behind the tip rather than the
106–112 of confirmation depth.

### Measured on live mainnet

`scripts/verify_attestations.py`, 120 consecutive headers (117259828–117259947,
`bsc-dataseed.bnbchain.org`, 2026-08-21):

| Observed | Result |
|----------|--------|
| Attestation present | **120 / 120** (no header lacked one) |
| Target == direct parent | 120 / 120 |
| Source chain continuity | 120 / 120 |
| Justification lag (`number - target`) | **1**, flat — min = max = median |
| **Finalization lag** (`number - source`) | **2**, flat — min = max = median |
| Vote participation | 20/21 on 117 blocks, 19/21 on 1, 17/21 on 2 |
| Blocks meeting the 14-of-21 quorum | 120 / 120 |
| `Extra` length | **0** bytes on every block (cap 256) |

So the finalized head sits **2 blocks** behind the tip against **106–112** for
confirmation depth — a ~53–56x reduction in distance-to-tip. For `eth_getProof` that
relaxes the required **window depth** from ~112 blocks to ~3; it does not relax the
requirement that a provider serve proofs **by number or hash at all**. See
[below](#what-this-does-and-does-not-fix-for-eth_getproof).

Two caveats worth keeping in view:

- **Lag 2 is the observed norm, not a proven bound.** It was constant over 120 blocks in
  a healthy period. Under validator churn or a stalled vote round the source can trail
  further, and the attestation-absent case (seen 0 times here) is still legal.
- The script proves attestations are *present, well-formed and structurally consistent*.
  It does **not** check the BLS signature — that happens only in
  `crates/helios-bsc-consensus/src/vote.rs`.

Reproduce:

```bash
python scripts/verify_attestations.py --rpc https://bsc-dataseed.bnbchain.org --blocks 120
```

## Implementation status

| Piece | Where | State |
|-------|-------|-------|
| Attestation RLP decode (strict, canonical-only) | `crates/helios-bsc-consensus/src/vote.rs` | **Done** |
| `VoteData.Hash()` = `keccak256(RLP(...))` | same | **Done** |
| Aggregate BLS verify (`blst`, min_pk, POP DST) | same | **Done** — verifies the real signatures on all five mainnet fixture headers |
| Bitset → sorted validator mapping, `ceil(2N/3)` quorum | same | **Done** |
| Target-is-parent / source-is-justified linkage | `snapshot.rs` `check_attestation` | **Done** — from Fermi the target may be any of 3 ancestors |
| Set selection at `TargetNumber - 1` | `snapshot.rs` `attestation_set` | **Done** — one generation of history kept |
| Justified / finalized tracking | `snapshot.rs` `justified()` / `finalized()` | **Done** |
| Vote keys carried in the checkpoint | `helios-bsc-types`, `write-checkpoint --sealing-set-from-epoch` | **Done** |
| Exposed on `helios_bsc_syncStatus` + `/metrics` | `bin/helios-bsc/src/rpc_server.rs` | **Done** |
| `latest` / `safe` / `finalized` served from BLS finality | `run` (default since 2026-08-25) | **Done, default.** The ≥24h soak that gated it passed 2026-08-24 (24.06 h, exit 0) and a 4 h soak on the shipped build followed (2871 comparisons, 0 mismatch, 99 `parlia_*` cross-checks). `--finality confirmation-depth` pins the old rule. |
| Maxwell BEP-524 `recents` prune to the finalized head | `snapshot.rs` `prune_recents_to_finalized` | **Done** |
| Justified / finalized cross-checked against geth | `soak --finality fast`, `diff_finality_one` | **Done** — compares this client's pair with `parlia_getJustifiedNumber` / `parlia_getFinalizedNumber` at the snapshot's own block. Everything above verifies the attestation path against itself; this is the only check that asks an independent geth whether the answer is right. The soak fails closed if it never produced a verdict, so the oracle must serve the `parlia_` namespace — most public BSC endpoints answer `-32601`. |

## Serving reads from the finalized head

`run --finality fast` makes `latest` / `safe` / `finalized` — and the ceiling on
historical reads — resolve to the BLS-finalized head rather than the confirmation-depth
Safe head. Three rules keep that from being a downgrade:

- **Never a block we did not verify.** The finalized head is used only when the
  attestation's `(number, hash)` matches a block already in the local verified chain. An
  attestation naming a block this client never walked is an upstream's word, not a head.
- **Never backwards.** If BLS finality stalls behind confirmation depth, tags stay on the
  confirmation-depth head. Both are complete finality rules, so taking the newer of the
  two means the head is final under at least one of them either way — enabling the flag
  can only make reads fresher.
- **Never silently.** `helios_bsc_syncStatus.safeSource` says which rule chose the current
  head, and `distinctSealers` / `requiredSealers` keep describing confirmation depth
  rather than being retyped into vote counts.

### What this does and does not fix for `eth_getProof`

It changes the **depth** a provider must retain, not the **addressing mode** it supports.
A proof at ~2 blocks needs a by-number/by-hash window of ≥3 blocks where ~112 was needed
before — which brings the shallow-window providers in
[proof-provider-matrix.md](./proof-provider-matrix.md) into range, including ones whose
window is far too small for confirmation depth.

It does **not** help a **tag-only** provider. Measured 2026-08-21: with
`bsc-rpc.publicnode.com` and `--finality fast`, `helios_bsc_syncStatus` correctly showed
`safe = tip - 2`, and `eth_getBalance` still failed:

```text
-32001 proof_verification_failed: by-number: rpc error:
  {"code":-32602,"message":"distance to target block exceeds maximum proof window"}
```

That endpoint rejects proofs by number or hash at *any* distance, including at the tip, so
no finality rule can rescue it. The matrix already records it as a gate fail for exactly
this reason; fast finality does not change that verdict.

On a provider that *does* address blocks, the change is decisive. `bsc-mainnet.public.blastapi.io`
is free and needs no key; its proof window ends somewhere between lag 64 and 96, which is a
hard fail at ~112 and ample at 2. Running against it with `--finality fast`, head at
`tip - 2`:

- `eth_getBalance`, `eth_getStorageAt` (WBNB slot 0 → `"Wrapped BNB"`) and `eth_call`
  (`totalSupply`) all returned MPT-verified values.
- Differential at a pinned block against two independent blind oracles (publicnode,
  meowrpc): **8 addresses, 8 match, 0 mismatch, 0 skip.**

That is the Phase 0 `eth_getProof` gate, which had been stuck at PARTIAL PASS on exactly
this constraint. See [proof-provider-matrix.md](./proof-provider-matrix.md).

One caveat about the differential above, because it bit me while measuring: compare at a
**pinned block number**, never at `latest`. WBNB's balance changes every block, so two
requests a second apart legitimately disagree — an artefact that looks exactly like a
verification failure.

It stays opt-in because changing what `latest` means to a wallet is a behavioural change,
and the ≥24h differential soak is the gate for making it the default.

## Trust model

Fast Finality is **stronger** than the confirmation-depth Safe head, not a shortcut:

| | Confirmation depth | Fast Finality |
|--|--|--|
| Evidence | ≥15 distinct sealers *built on top of* the block | ≥14 validators **cryptographically signed** the block |
| Forgeable by | 15-of-21 colluding validators | 14-of-21 colluding validators, and the signatures are attributable |
| Lag | 106–112 blocks | a few blocks |

The reduction from 15 to 14 signers is the protocol's own threshold, and unlike
confirmation depth the votes are non-repudiable — a lying RPC cannot manufacture them,
and a colluding validator set leaves signed evidence. Both live inside the sealed
header, so neither can be restated by an upstream without breaking the ECDSA seal.

## Fail-closed rules specific to this module

- **No vote keys ⇒ no fast finality.** Vote keys arrive only in epoch `extraData`. A
  checkpoint written from `--sealing-set` (operator addresses) carries none, so a fresh
  process runs confirmation-depth until it ingests and activates an epoch header. The
  client never guesses a key and never infers one from an attestation.
- **A present-but-invalid attestation rejects the header.** Absent is fine; wrong is
  fatal. Anything else would let an upstream strip attestations to downgrade the client
  silently — and stripping is already prevented by the seal.
- **The finalized head must exist in the locally verified chain.** An attestation naming
  a hash the client has not verified is rejected rather than trusted on its own word.
- A bit set at an index ≥ `N` names no validator. geth catches most of these through the
  `popcount ≤ N` comparison; this client rejects them outright.

## Not covered here

- **Vote propagation / the vote pool.** A light client only reads attestations already
  embedded in sealed headers; it does not gossip votes.
- **Maxwell BEP-524 `recents` prune to the finalized head.** It depends on this module
  and is tracked separately in [STATUS.md](../STATUS.md).
- **Slashing evidence** (`VoteData` double-sign detection). Out of scope for a read-only
  client.
