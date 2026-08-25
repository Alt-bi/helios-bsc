# Proof-fail storm

`eth_getProof` at the read head returns `historical state not available`, `-32001`, or a
window error. Wallet `eth_getBalance("latest")` must **fail closed**, not fall back to tip.

**First establish which head you are on.** Since 2026-08-25 the default is the BLS-finalized
head at lag ~2, where almost any provider can serve proofs — a storm there is usually the
provider, not the window. The ~108–112 lag this runbook was written for is what
`--finality confirmation-depth` asks for, and what a client without BLS vote keys falls back
to. `helios_bsc_syncStatus.safeSource` and the startup line both name the rule in force.

## Immediate

1. `helios_bsc_syncStatus` — check `lag` / `safeLagBlocks` / `safeLagSeconds` / `safeLagWithinBound`, `inProofWindow`, `distinctSealers` (≥15), `finality`, `sealingSetEnforced`, `proofFail` (process lifetime). See [SLOs](../slo.md).
2. If `safeSource` is `confirmation-depth` when you expected `fast-finality`, the checkpoint
   carries no BLS vote keys — rewrite it (`write-checkpoint` does this by default) rather
   than hunting a deeper provider.
3. If `lag > 112` on confirmation depth: wait or swap the proof RPC. Do **not** lower the
   15-sealer rule.
4. If `inProofWindow` is true but proofs still fail: provider jitter. Retry by **hash**, then **number**. Still failing → swap key (Ankr free is knife-edge; paid/archive is the next step).
5. Soak: `helios-bsc soak --oracle <other-host> --once`. Oracle skips (no historical state) are not mismatches. Mismatch = incident.

## Do not

- Map `latest` to upstream tip.
- Treat 100 or 110 blocks as Safe.
- Use the same RPC host as both data plane and soak oracle.
- Invent a sealing set from recent `miner` fields.

## After

Log provider + lag + error text (no API keys). Update `docs/proof-provider-matrix.md` if a new cutoff appears. Persist last-verified checkpoint so restart does not re-walk from a stale file.
