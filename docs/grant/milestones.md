# Grant milestones — helios-bsc ($8,000)

**Total ask: USD 8,000** · Solo developer · Open source (MIT OR Apache-2.0)

Payment on delivery of each milestone (typical Builder Grant style).

---

## Milestone 1 — Public Demo Slice release — **$4,000**

**Target:** 4–6 weeks after grant agreement

**Deliverables:**

1. Public GitHub repository `helios-bsc` with MIT OR Apache-2.0.  
2. Tagged release **v0.1.0** (or `v0.1.0-demo`) with changelog.  
3. README + design docs: architecture, RPC method matrix, checkpointing, proof-provider matrix.  
4. CI green (`cargo test --workspace`).  
5. Short demo recording (commands: `info`, `probe-safe` / `run`, `helios_bsc_syncStatus`).  
6. Clear documentation of Safe-lag proof-window limitation and operator runbook.

**Acceptance:** Reviewer can clone, `cargo test`, and reproduce Demo Slice against a documented upstream.

---

## Milestone 2 — Stable verified reads path + integration guide — **$4,000**

**Target:** +6–8 weeks after M1

**Deliverables:**

1. **Reproducible Safe-lag `eth_getProof` path** documented end-to-end:  
   - either a paid/archive-capable provider matrix row that passes at Safe lag (~108–120+), **or**  
   - Alt F runbook (self-hosted full/fast as untrusted proof plane) with soak results.  
2. Written soak report: `helios-bsc soak --oracle <independent>` (or equivalent) over a meaningful window.  
3. **Wallet / integrator short guide**: point MetaMask/custom RPC or `cast`/`ethers` at local helios-bsc; which methods are verified vs unsupported.  
4. Optional stretch: small hardening PRs from soak findings (no scope creep into full `eth_call` unless spare capacity).

**Acceptance:** Independent reviewer can follow docs and obtain verified `eth_getBalance` at Safe without silent passthrough; Phase 0 proof gate marked pass or Alt F pass in docs.

---

## Out of scope for this $8k grant

- Full Fast Finality BLS verification productization  
- Constrained `eth_call` as a hard deliverable (may appear as stretch)  
- Hosting a commercial SaaS  
- Multi-chain (ETH/SOL) ports  

---

## Budget sketch (same $8,000)

| Item | Approx. |
|------|--------:|
| Engineering time (solo) for M1+M2 | $6,500 |
| Paid BSC RPC / small VPS for Alt F proofs (2–3 months) | $1,000 |
| Contingency (domain, recording, misc) | $500 |
| **Total** | **$8,000** |
