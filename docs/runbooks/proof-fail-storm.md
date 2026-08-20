# Proof-fail storm

`eth_getProof` at Safe (lag ~108–112) returns `historical state not available`, `-32001`, or a window error. Wallet `eth_getBalance("latest")` must **fail closed**, not fall back to tip.

## Immediate

1. `helios_bsc_syncStatus` — check `lag` / `safeLagBlocks` / `safeLagSeconds` / `safeLagWithinBound`, `inProofWindow`, `distinctSealers` (≥15), `finality`, `sealingSetEnforced`, `proofFail` (process lifetime). See [SLOs](../slo.md).
2. If `lag > 112`: wait or swap the proof RPC. Do **not** lower the 15-sealer rule.
3. If `inProofWindow` is true but proofs still fail: provider jitter. Retry by **hash**, then **number**. Still failing → swap key (Ankr free is knife-edge; paid/archive is the next step).
4. Soak: `helios-bsc soak --oracle <other-host> --once`. Oracle skips (no historical state) are not mismatches. Mismatch = incident.

## Do not

- Map `latest` to upstream tip.
- Treat 100 or 110 blocks as Safe.
- Use the same RPC host as both data plane and soak oracle.
- Invent a sealing set from recent `miner` fields.

## After

Log provider + lag + error text (no API keys). Update `docs/proof-provider-matrix.md` if a new cutoff appears. Persist last-verified checkpoint so restart does not re-walk from a stale file.
