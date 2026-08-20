# Operator SLOs (MVP-1)

These are **operator freshness bounds**, not protocol constants. Confirmation-depth Safe is still **15 distinct subsequent sealers**; a lag above the in-turn upper bound does not make a 15-sealer head un-Safe.

| SLO | Default | Where |
|-----|---------|--------|
| Checkpoint max age | **24h** (`--max-checkpoint-age-hours`) | fail-closed unless `--allow-stale-checkpoint` |
| Checkpoint warn | **6h** | stderr + `doctor` `slo=warn` |
| Safe lag (in-turn upper) | **120** blocks / **~54s** (`15 × turnLength=8 × 450ms`) | `syncStatus.expectedSafeLagBlocks` / `safeLagWithinBound` |
| Live Safe lag | **~108–112** blocks / **~48–50s** | measured, not a gate |
| Proof window | **112** blocks (Ankr free) | fail-closed if Safe lag > window |
| Sync catch-up | checkpoint ≤ `--max-sync` (16000, ~2 h) behind tip | fail-closed; refresh the file. `--lookback` 130 is the no-checkpoint Safe window only. |

`helios-bsc doctor` labels `checkpoint.json` `slo=ok|warn|fail` from age only (never prints keys or the sealing-set list). `helios_bsc_syncStatus.safeLagWithinBound` is `true` when `lag ≤ 120`. Serving continues if lag is higher but 15 sealers exist — that is a valid out-of-turn stretch, not a protocol failure.

Wallet mode still maps `latest` → Safe. Do not alert “head is stale” merely because Safe is ~1 minute behind tip.
