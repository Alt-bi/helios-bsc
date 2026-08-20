# Checkpoints

Root of trust for Parlia light sync: block **number**, **hash**, **parentHash**, **stateRoot**, and the **sealing set** active at that height. A bad checkpoint follows the wrong chain.

## What is not inferred

The sealing set is **operator-supplied**. The client never builds it from miners in a lookback window (those can be the next epoch set, or an eclipse). Epoch `extraData` validators are the *next* set, delayed by `minerHistoryCheckLen` (87 at N=21, T=8). `--sealing-set-from-epoch` reads that extraData only after the delay has elapsed at `--block`.

## Commands

```bash
# Create from a trusted header + explicit 21 addresses (never from recent miners)
helios-bsc write-checkpoint --block 0x… --sealing-set 0xabc,0xdef,… --out checkpoint.json

# Or take the set from an *activated* epoch extraData (the *next* set at that epoch).
# Epoch E activates at E+87 (N=21,T=8). Checkpoint height must be ≥ that.
helios-bsc write-checkpoint --block 0x… --sealing-set-from-epoch 0x… --out checkpoint.json

# Check file vs upstream (no 130-header walk)
helios-bsc verify-checkpoint --checkpoint checkpoint.json

# Second source must agree (different RPC host)
helios-bsc verify-checkpoint --checkpoint checkpoint.json \
  --require-multisource-checkpoint \
  --checkpoint-oracle https://bsc-mainnet.public.blastapi.io

# Sync with membership + persist last-verified back to the file
helios-bsc run --checkpoint checkpoint.json
```

`run` / `probe-safe` / `soak --checkpoint` walk `checkpoint.number+1 ..= tip` with ECDSA seal, parent-link, sealing-set membership, in-turn difficulty, and Bohr `SignRecently`. Tip more than `--max-sync` (default 16000, ~2 h) behind the file → fail-closed (refresh the checkpoint). `--lookback` (130) is only the no-checkpoint Safe window, not the restart budget. Recents start empty at the checkpoint (pre-checkpoint history is not inferred).

## Age

Default max **24h** (`--max-checkpoint-age-hours`). Warn after **6h**. `--allow-stale-checkpoint` continues anyway. Persist writes the last *verified* header (not Safe); Safe is recomputed after the walk.

Without `--checkpoint`, `run` only checks seals + parents. `helios_bsc_syncStatus.sealingSetEnforced` is then `false` (stderr warning). `--require-checkpoint` makes that a hard error.
