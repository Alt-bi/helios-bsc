# Checkpoints

Root of trust for Parlia light sync: block **number**, **hash**, **parentHash**, **stateRoot**, and the **sealing set** active at that height. A bad checkpoint follows the wrong chain.

## What is not inferred

The sealing set is **operator-supplied**. The client never builds it from miners in a lookback window (those can be the next epoch set, or an eclipse). Epoch `extraData` validators are the *next* set, delayed by `minerHistoryCheckLen` (87 at N=21, T=8). `--sealing-set-from-epoch` reads that extraData only after the delay has elapsed at `--block`.

## Commands

Every command below needs an upstream. `--upstream` is shown explicitly; it also reads
`HELIOS_BSC_UPSTREAM`, and `--checkpoint-oracle` reads `HELIOS_BSC_CHECKPOINT_ORACLE`.

```bash
# The normal case: derive the sealing set, and have a second host confirm the header.
# --sealing-set-from-epoch is optional — it is derived from --block when omitted.
helios-bsc write-checkpoint   --upstream https://bsc-rpc.publicnode.com   --checkpoint-oracle https://bsc-dataseed.bnbchain.org   --block latest   --out checkpoint.json

# Operator-supplied set instead: explicit addresses, never inferred from recent miners.
# This form carries no BLS vote keys, so the client starts at confirmation depth.
helios-bsc write-checkpoint   --upstream https://bsc-rpc.publicnode.com   --block 0x… --sealing-set 0xabc,0xdef,…   --out checkpoint.json

# Pin the epoch by hand. Epoch E activates at E+87 (N=21, T=8); --block must be >= that.
helios-bsc write-checkpoint   --upstream https://bsc-rpc.publicnode.com   --block 0x… --sealing-set-from-epoch 0x…   --out checkpoint.json

# Check an existing file against upstream (no 130-header walk).
helios-bsc verify-checkpoint   --upstream https://bsc-rpc.publicnode.com   --checkpoint checkpoint.json

# Require a second, independent host to agree (must not be the same RPC).
helios-bsc verify-checkpoint   --upstream https://bsc-rpc.publicnode.com   --checkpoint checkpoint.json   --require-multisource-checkpoint   --checkpoint-oracle https://bsc-dataseed.bnbchain.org

# Sync with membership enforced; the last verified header is persisted back to the file.
helios-bsc run   --upstream https://bsc-rpc.publicnode.com   --checkpoint checkpoint.json
```

Confirming the checkpoint at the moment it is written is better than confirming it
afterwards: every later check is relative to it, so a checkpoint two independent hosts
disagree on is never written at all. Without an oracle the command warns and continues.

`run` / `probe-safe` / `soak --checkpoint` walk `checkpoint.number+1 ..= tip` with ECDSA seal, parent-link, sealing-set membership, in-turn difficulty, and Bohr `SignRecently`. Tip more than `--max-sync` (default 16000, ~2 h) behind the file → fail-closed (refresh the checkpoint). `--lookback` (130) is only the no-checkpoint Safe window, not the restart budget. Recents start empty at the checkpoint (pre-checkpoint history is not inferred).

## BLS vote keys (Fast Finality)

`--sealing-set-from-epoch` also writes the epoch's **BLS vote keys** into the checkpoint
as `voteKeys`, positionally aligned with `sealingSet`. `--sealing-set` cannot: operator
addresses carry no keys, and the client never guesses one or infers it from an
attestation.

The field is optional and `#[serde(default)]`, so older checkpoint files stay loadable.
`validate_basic` rejects a `voteKeys` list of the wrong length, a key that is not 48
bytes, or a duplicate — a mispaired address and key would only ever show up as an
aggregate signature failing for the wrong reason.

Consequence for the operator:

| Checkpoint written with | `finality` on `helios_bsc_syncStatus` |
|--|--|
| `--sealing-set-from-epoch` | `fast-finality` right away |
| `--sealing-set` (addresses only) | `confirmation-depth` until the client ingests **and activates** an epoch header for itself (≤1000 blocks + 87) |

`verify-checkpoint` prints which of the two a file is. Restart keeps the keys: the
last-verified checkpoint carries them forward, so a restart does not silently drop to
confirmation depth. See [fast-finality.md](./fast-finality.md).

## Age

Default max **24h** (`--max-checkpoint-age-hours`). Warn after **6h**. `--allow-stale-checkpoint` continues anyway. Persist writes the last *verified* header (not Safe); Safe is recomputed after the walk.

Without `--checkpoint`, `run` only checks seals + parents. `helios_bsc_syncStatus.sealingSetEnforced` is then `false` (stderr warning). `--require-checkpoint` makes that a hard error.
