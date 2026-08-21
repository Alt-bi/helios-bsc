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

## Prometheus metrics (opt-in)

`helios-bsc run --metrics` serves the Prometheus text format on `GET /metrics` at the same bind. **Off by default**; it is the only non-POST route, and the loopback `Host` check applies to it exactly as to JSON-RPC.

| Metric | Type | Meaning |
|--------|------|---------|
| `helios_bsc_headers_verified_total` | counter | Headers whose seal + parent link verified |
| `helios_bsc_header_verify_fail_total` | counter | Sync rejected **after** the tip was fetched (seal / parent link / no Safe) |
| `helios_bsc_proof_success_total` | counter | MPT proofs verified against a Safe `stateRoot` |
| `helios_bsc_proof_fail_total` | counter | MPT proofs rejected — the number to alert on |
| `helios_bsc_upstream_errors_total` | counter | Transport failures fetching the tip |
| `helios_bsc_tip_block` / `helios_bsc_safe_block` | gauge | Local tip / Safe head |
| `helios_bsc_safe_lag_blocks` / `_seconds` | gauge | Tip − Safe |
| `helios_bsc_safe_lag_within_bound` | gauge | 1 inside the bound above, else 0 |
| `helios_bsc_checkpoint_age_seconds` | gauge | Origin checkpoint age |
| `helios_bsc_finality_mode` | gauge | 0 = confirmation-depth, 1 = fast finality (not implemented) |
| `helios_bsc_sealing_set_enforced` | gauge | 1 with `--checkpoint`, else 0 |
| `helios_bsc_unverified_passthrough_enabled` | gauge | 1 when passthrough is on |

Two deliberate properties:

- **A scrape is lock-free and does no network I/O.** Gauges are published to atomics after each sync, so a scrape never queues behind the chain lock and never adds upstream load. This is load-bearing: an earlier build took the chain mutex and a live scrape **hung for 180 s** behind a slow serial header walk — metrics disappeared exactly when they were needed. `metrics_do_not_take_the_chain_lock` guards the regression.
- **Unknown is `-1`, never `0`.** Before the first Safe head, `tip_block` / `safe_block` / `safe_lag_*` / `checkpoint_age_seconds` report `-1`, so a dashboard cannot read "not synced yet" as "zero lag".

Separate the two failure counters when alerting: `upstream_errors` rising alone is a flaky provider; `proof_fail` or `header_verify_fail` rising is a **lying upstream** — see [runbooks/proof-fail-storm.md](runbooks/proof-fail-storm.md).
