# Consensus appendix (Phase 0 normative pins)

**Status:** pinned to `bnb-chain/bsc` **v1.7.8** (`cdb7548b5baacfdae92f9f63437d6456411665f3`).  
PR 4 (ECDSA seals) may start from this appendix + epoch-boundary fixtures.

## Upstream pointers

All paths relative to https://github.com/bnb-chain/bsc/tree/v1.7.8

| Concern | File | Symbol |
|---------|------|--------|
| Constants (epoch / interval / extra sizes / difficulties) | `consensus/parlia/parlia.go` | `defaultEpochLength`, `lorentzEpochLength`, `maxwellEpochLength`, `*BlockInterval`, `extraVanity`, `extraSeal`, `validatorBytesLength`, `diffInTurn`, `diffNoTurn` |
| extraData parse (epoch validators) | `consensus/parlia/parlia.go` | `getValidatorBytesFromHeader` |
| extraData parse (FF attestation) | `consensus/parlia/parlia.go` | `getVoteAttestationFromHeader` |
| Seal recover | `consensus/parlia/parlia.go` | `ecrecover` |
| Seal hash (header without 65-byte seal, **includes chainId**) | `core/types` via `types.SealHash(header, chainId)` | used by `ecrecover` |
| Block hash | `core/types/block.go` `Header.Hash()` | keccak256(RLP(header)); extra **includes** seal; no chainId. Optional London+ tail is `gen_header_rlp.go` |
| Structural header checks | `consensus/parlia/parlia.go` | `VerifyUnsealedHeader`, `verifyCascadingFields` |
| Seal + coinbase match + FF | `consensus/parlia/parlia.go` | `verifySeal` |
| Snapshot / set switch | `consensus/parlia/snapshot.go` | `Snapshot.apply` |
| Epoch-set activation delay | `consensus/parlia/snapshot.go` | `minerHistoryCheckLen`, applied when `number % epochLength == minerHistoryCheckLen()` |
| In-turn selection | `consensus/parlia/snapshot.go` | `inturnValidator`, `inturn` |
| Difficulty | `consensus/parlia` | `calcDifficulty(snap, coinbase)` → `2` in-turn / `1` out-of-turn |
| Parse validators / turnLength | `consensus/parlia/snapshot.go` | `parseValidators`, `parseTurnLength` |
| Fork times | `params/config.go` | `BSCChainConfig` |
| FF quorum | `consensus/parlia/parlia.go` `verifyVoteAttestation` | `cmath.CeilDiv(len(snap.Validators)*2, 3)` |

## extraData layouts (bytes)

`extraVanity = 32`, last 4 of vanity = `nextForkHash`. Seal is always the last 65 bytes.

### Pre-Luban

```text
| vanity 32 | validators (20 * N) or empty | seal 65 |
```

Validators present **only** on epoch blocks (`number % epochLength == 0`).

### Luban → Bohr (non-epoch)

```text
| vanity 32 | vote attestation RLP (or empty) | seal 65 |
```

### Luban → Bohr (epoch)

```text
| vanity 32 | n:u8 | n * (addr20 + bls48) | vote attestation RLP | seal 65 |
```

### Bohr+ (epoch) — **current mainnet**

```text
| vanity 32 | n:u8 | n * (addr20 + bls48) | turnLength:u8 | vote attestation RLP | seal 65 |
```

### Bohr+ (non-epoch) — **current mainnet**

```text
| vanity 32 | vote attestation RLP (or empty) | seal 65 |
```

`n` is **21** on live mainnet. Each validator record is **68 bytes** (20-byte address + 48-byte BLS key).
`turnLength` is **8** on live mainnet, read from the epoch header — never assume it. The constant
`defaultTurnLength` in the pinned source is **1**; the **16** that appears in a `snapshot.go`
comment is geth anticipating a future value, not one this chain has used. Hard-coding either is
the mistake this appendix exists to prevent.

## Seal verification (MVP-1, per header)

```text
assert len(extra) >= 32 + 65
seal = extra[-65:]
digest = SealHash(header_with_seal_zeroed_or_omitted, chainId=56)   # types.SealHash
pubkey = ecrecover(digest, seal)
signer = keccak256(pubkey[1:])[12:]
assert sha3Uncles == EMPTY_UNCLE_HASH
assert gasUsed <= gasLimit <= 2^63-1
assert mixDigest milliseconds (Lorentz+: MilliTimestamp/1000 == time; else zero)
assert parentBeaconRoot is zero hash (Bohr+)
assert header.Time <= now + 15s                 # Parlia verifyHeader future-block (15s skew)
assert nonce == 8 zero bytes                    # Parlia prepare uses empty nonce
assert keccak256(RLP(header)) == header.hash   # geth Header.Hash(); binds identity used in parent links
assert epoch extraData parses (n≥1 unique records; Bohr turnLength 1..=64)  # membership still --checkpoint
assert withdrawalsRoot is empty MPT (Cancun+ / present)
assert baseFeePerGas == 0 after London (31_302_048), absent before
    # CalcBaseFee opens `if config.IsInBSC() { return InitialBaseFeeForBSC }`; IsInBSC() is
    # `Parlia != nil` and the constant is 0, so BSC has no parent baseFee formula at all.
assert MilliTimestamp >= parent.MilliTimestamp + BlockInterval   # Ramanujan floor (backOffTime == 0, i.e. in-turn)
assert difficulty != 1 or MilliTimestamp >= parent.MilliTimestamp + BlockInterval + initialBackOff
    # out-of-turn refinement; initialBackOff = 2000ms if parent past Lorentz else 1000ms.
    # geth adds backOffSteps[idx]*wiggleTime from a Go math/rand shuffle we cannot reproduce;
    # that term is >= 0, so dropping it under-estimates the floor and never rejects an honest block.
    # No-op unless: sealing set trusted, parent millisecond walked, countRecents window fully
    # walked, and the in-turn validator has NOT signed recently (which is what zeroes geth's delay).
assert |gasLimit - parent.gasLimit| < parent.gasLimit / 1024 (Lorentz+; 256 pre-Lorentz) and gasLimit >= 5000
assert signer == header.coinbase
assert signer ∈ active_sealing_set
assert difficulty == (2 if signer == inturn_validator else 1)   # implemented on snapshot path
assert not SignRecently(signer)   # Bohr+: seenTimes >= turnLength in minerHistoryCheckLen window
```

`inturn_validator` at snapshot of parent (`snap.Number` = parent number):

```text
validators = sort_ascending(active_set)          # 20-byte address order
offset = (snap.Number + 1) / turnLength % N_seal
inturn = validators[offset]
```

## Epoch-set activation (replaces naive “N/2 blocks”)

```text
minerHistoryCheckLen := (N_seal / 2 + 1) * turnLength - 1
# N=21, T=8 (live fixture) → (10+1)*8 - 1 = 87
# N=21, T=16 (source comment only) → 175

# In Snapshot.apply, after applying header `number`:
if number > 0 and number % epochLength == minerHistoryCheckLen:
    checkpoint = header at (number - minerHistoryCheckLen)   # the epoch header
    parse validators + turnLength from checkpoint.extraData
    replace snap.Validators (Bohr+: clear Recents)
```

So the set published at epoch height `E` (`E % 1000 == 0`) becomes active at height `E + 87` with live T=8.

Legacy `turnLength = 1` collapses this to `N/2` (`(21/2+1)*1 - 1 = 10`).

## Confirmation-depth Safe (MVP-1, independent of FF)

```text
min_distinct_sealers := floor(2 * N_seal / 3) + 1    # 21 → 15
# Walk verified headers; count distinct coinbase/signers.
# Newest Safe = highest S such that distinct(miners in (S, tip]) ≥ 15.
# MVP-1 fork choice: lookback resync after a link-break must overlap the
# previous local chain within max_reorg_depth = N_seal (=21). Deeper → fail-closed.
# 15 * turnLength (=120 @ T=8) is an in-turn UPPER estimate, not a fixed offset.
# Live 2026-08-18 (200 headers, all in-turn): newest-Safe lag = 108–112.
# 100 blocks → ~13 distinct; 110 → ~14. Those are NOT Safe.
```

Do **not** use `ceil(2N/3)+1` as a general “>⅔” (wrong for some N).  
FF uses `ceil(2N/3)` (≥⅔) — different predicate, MVP-2 only.

## Fast Finality (Phase 0 availability note)

**Gate: PASS (data is in the header, not a special RPC method).**

Post-Luban headers embed an RLP `VoteAttestation` in `extraData`:

```text
VoteAttestation {
  VoteAddressSet  // bitfield, validator index = ValidatorInfo.Index - 1
  AggSignature    // aggregated BLS
  Data { SourceNumber, SourceHash, TargetNumber, TargetHash }
  Extra
}
```

- Quorum: `ceil(2 * N_vote / 3)` of the **sealing set’s vote keys** (same N as N_seal on current mainnet).
- `Snapshot.Attestation.Source*` is treated as the FF **finalized** block.
- Public `eth_getBlockByNumber/Hash` returns `extraData`; no extra RPC field is required.
- Plato+ (`block ≥ 30_720_096`): invalid attestation **rejects** the header.
- Fermi+: attestation target may be an ancestor up to `kAncestorGenerationDepth = 3`, not only the parent.

**BLS is verified** as of MVP-2: the aggregate signature is checked against the epoch vote keys
(`blst`, min_pk, POP DST) over `keccak256(RLP(VoteData))`, with the bitset mapped onto the sealing
set sorted by address. See [fast-finality.md](./fast-finality.md). Fixtures keep raw `extraData`.

## Light-client rules (MVP-1)

1. Start from a multisource **checkpoint** ≤ 24h (hash, number, stateRoot, sealing set, fork_id).
2. Parent-link walk; verify ECDSA seal ∈ current sealing set; coinbase == signer; difficulty matches in-turn.
3. On `number % epochLength == minerHistoryCheckLen`: activate the set + turnLength from the epoch header at `number - minerHistoryCheckLen`.
4. **Safe** head: ≥ `floor(2N/3)+1` distinct sealers observed (15 for N=21).
5. Expected Safe lag ≈ `O(15 * turnLength)` blocks. Live T=**8** → ~120 blocks ≈ 54 s @ 0.45 s.

## Pseudo-code (normative-intent, matches v1.7.8)

```text
snap = snapshot_from_checkpoint(C)          # Validators, TurnLength, EpochLength
safe = None
seen = {}

for h in headers_from_checkpoint:
    assert h.number == prev.number + 1
    assert h.parent_hash == prev.hash
    signer = ecrecover(SealHash(h, 56), h.extra[-65:])
    assert signer == h.coinbase
    assert signer in snap.Validators
    assert not snap.SignRecently(signer)
    inturn = snap.inturnValidator()         # based on snap.Number (= parent)
    assert h.difficulty == (2 if signer == inturn else 1)
    snap.apply(h)                           # recents + optional epoch switch at minerHistoryCheckLen
    seen.add(signer)
    if len(seen) >= floor(2 * len(snap.Validators) / 3) + 1:
        safe = some_ancestor_meeting_policy(h)   # confirmation-depth head
```

## Fixture coverage (all closed)

- Real epoch-boundary `extraData` at `number % 1000 == 0` and the following non-epoch header —
  `fixtures/mainnet/`, epoch 116664000 ±2, live `n=21`, `turnLength=8`.
- Mutated-seal and mutated-proof fail vectors — in the adversarial suite.
- Live `eth_getProof` by hash/number — [proof-provider-matrix.md](./proof-provider-matrix.md).
