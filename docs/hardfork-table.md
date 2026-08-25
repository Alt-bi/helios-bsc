# BSC Parlia hardfork / network parameter table

**Status:** pinned to production tag `bnb-chain/bsc` **v1.7.8**.

Upstream: https://github.com/bnb-chain/bsc  
Consensus package: `consensus/parlia`  
Config source: `params/config.go` `BSCChainConfig`

## Pin record

| Field | Value |
|-------|-------|
| `bnb-chain/bsc` tag | **v1.7.8** (latest non-prerelease as of 2026-08-18) |
| Commit SHA | `cdb7548b5baacfdae92f9f63437d6456411665f3` |
| Date verified | 2026-08-18 |
| Verified by | helios-bsc Phase 0 (source read of `params/config.go` + `consensus/parlia/{parlia,snapshot}.go`) |
| Note | `master` at this date is `v1.8.0-alpha` — **do not pin master**. Pasteur (`PasteurTime = 1787625000` = 2026-08-25 02:30 UTC) went **live 2026-08-25**; the pin already contained it and it changes no Parlia rule, so no client change was needed. Walked live the same day: checkpoint at 117956350 reports `forkId=pasteur`, and a soak on the post-Pasteur chain matched an independent oracle on 116 comparisons with 0 mismatches. |

Re-pin after Pasteur (2026-08-25) if extraData / epoch / turnLength change (they are not expected to).

## Light-client-relevant constants (`consensus/parlia/parlia.go`)

| Symbol | Value | Meaning |
|--------|------:|---------|
| `defaultEpochLength` | 200 | Pre-Lorentz |
| `lorentzEpochLength` | 500 | Lorentz → Maxwell |
| `maxwellEpochLength` | **1000** | Maxwell+ (current) |
| `defaultBlockInterval` | 3000 ms | Pre-Lorentz |
| `lorentzBlockInterval` | 1500 ms | Lorentz |
| `maxwellBlockInterval` | 750 ms | Maxwell |
| `fermiBlockInterval` | **450 ms** | Fermi+ (current) |
| `defaultTurnLength` | 1 | Pre-Bohr default |
| Lorentz-era turnLength | 8 | Comment in `snapshot()`; live value is epoch-embedded post-Bohr |
| Maxwell-era turnLength (source comment) | 16 | Possible contract value; **not** assumed live |
| Live turnLength (fixture epoch 116664000) | **8** | Read from epoch extraData; authoritative |
| Light-client `MAX_TURN_LENGTH` | **64** | Not a geth constant; rejects extraData `turnLength` 0 or >64 |
| `extraVanity` | 32 | Prefix (last 4 = `nextForkHash`) |
| `extraSeal` | 65 | ECDSA seal suffix |
| `nextForkHashSize` | 4 | Vanity suffix |
| `turnLengthSize` | 1 | Epoch extra after Bohr |
| `validatorBytesLengthBeforeLuban` | 20 | Address only |
| `validatorBytesLength` | **68** | 20-byte address + 48-byte BLS vote key |
| `validatorNumberSize` | 1 | Epoch extra after Luban |
| `diffInTurn` | 2 | In-turn difficulty |
| `diffNoTurn` | 1 | Out-of-turn difficulty |

## Sealing set / Safe threshold

| Symbol | Meaning | Typical mainnet |
|--------|---------|-----------------|
| Elected active | Cabinet + Candidates | ~45 |
| **N_seal** | `len(snap.Validators)` this epoch | **21** |
| Safe threshold (MVP-1) | `floor(2*N_seal/3)+1` | **15** |
| Epoch-set activation delay | `minerHistoryCheckLen = (N/2+1)*turnLength - 1` | **87** blocks when N=21, T=**8** (live). 175 if T were 16. |

`N_seal/2` (design shorthand) is the **turnLength=1** special case of `minerHistoryCheckLen`. Do **not** implement a flat +10 block delay on Maxwell/Fermi mainnet.

## Mainnet fork schedule (from `BSCChainConfig`)

Times are Unix seconds. Block-number forks are absolute heights.

| Fork | Activation | epochLength | turnLength | blockInterval | extraData notes |
|------|------------|------------:|-----------:|--------------:|-----------------|
| Legacy / Ramanujan | genesis-era | 200 | 1 | 3.0 s | Clique-like vanity+vals+seal |
| **Luban** | block **29_020_050** | 200 | 1 | 3.0 s | + validator count byte + 48-byte BLS keys + RLP vote attestation |
| **Plato** | block **30_720_096** | 200 | 1 | 3.0 s | FF attestation **required** (`verifyVoteAttestation` fails closed) |
| **Bohr** | time **1_727_317_200** (2024-09-26 02:20 UTC) | 200 | epoch-embedded (4→8 later) | 3.0 s | + 1-byte `turnLength` on epoch extra |
| **Lorentz** | time **1_745_903_100** (2025-04-29 05:05 UTC) | **500** | 8 | **1.5 s** | MixDigest carries milliseconds |
| **Maxwell** | time **1_751_250_600** (2025-06-30 02:30 UTC) | **1000** | epoch-embedded (live **8**) | **0.75 s** | Recents pruned to FF source |
| **Fermi** | time **1_768_357_800** (2026-01-14 02:30 UTC) | 1000 | epoch-embedded (live **8**) | **0.45 s** | Attestation target may be ancestor (depth 3) |
| **Osaka / Mendel** | time **1_777_343_400** (2026-04-28 02:30 UTC) | 1000 | epoch-embedded (live **8**) | 0.45 s | Execution-layer; no Parlia extraData change observed |
| **Pasteur** | time **1_787_625_000** (2026-08-25 02:30 UTC) | 1000 (expected) | epoch-embedded (live **8**) | 0.45 s (expected) | Named in `params_at`; extraData family still Bohr. **Re-pin after activation if extraData/epoch/turnLength change.** |

## Current mainnet profile (2026-08-19)

Use this until Pasteur activates. After unix `1_787_625_000`, `params_at` names the fork `pasteur` with the **same** Parlia numbers below until a re-pin proves otherwise.

| Param | Value |
|-------|------:|
| `chainId` | 56 |
| `fork_id` | `fermi` (Mendel/Osaka execution-active; Parlia profile still Fermi) |
| `epoch_length` | 1000 |
| `turn_length` | **8** (from epoch extraData; do not hard-code 16) |
| `block_interval_ms` | 450 |
| `n_seal` | 21 |
| `min_distinct_sealers` | 15 |
| `miner_history_check_len` | **87** |
| `expected_safe_lag_blocks` | **108–120** (live 108–112; in-turn upper `15*8=120`) |
| `expected_safe_lag_seconds` | ~50–54 |

Do **not** implement seal codecs from memory — see [consensus-appendix.md](./consensus-appendix.md) for exact functions.
