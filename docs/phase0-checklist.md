# Phase 0 exit checklist

Must pass **before** consensus implementation PRs (seal verify / sync).

See also: [design.md](./design.md), [hardfork-table.md](./hardfork-table.md), [proof-provider-matrix.md](./proof-provider-matrix.md), [consensus-appendix.md](./consensus-appendix.md).

## Gates

- [x] **Hardfork table** pinned to a specific `bnb-chain/bsc` commit SHA (`docs/hardfork-table.md`) — **v1.7.8** `cdb7548b5baacfdae92f9f63437d6456411665f3`.
- [x] **Modern fixtures** across `epochLength=1000` boundary under `fixtures/mainnet/` — epoch **116664000** ±2 headers; live parse `n=21`, `turnLength=8`. extraData codec + ECDSA seal↔miner verified on all five headers.
- [x] **`eth_getProof` matrix**: Ankr **by number** works at lag **≤~108** (live 2026-08-19). Safe lag **106–112**. Hash often `not supported`. Catch-up after the header walk is required. Tag-only still does not count. BlastAPI public remains ~96 (oracle only).
- [x] If no public hash/number path: **Alt F** plan documented (remote full/fast as untrusted data plane) — operator order unchanged: paid key first, Alt F if paid also fails.
- [x] **FF / BEP-126** RPC field availability noted (pass → schedule FF PR; fail → defer forever for MVP-1). **PASS:** attestation lives in header `extraData` (`getVoteAttestationFromHeader`); no special RPC method required. MVP-1 still does not verify BLS.
- [x] **`docs/consensus-appendix.md`**: pointers into `parlia.go` / `snapshot.go` + pseudo-code for seals / epoch delay (`minerHistoryCheckLen`, not naive N/2).

## Operator policy (settled)

1. Measure **public/paid** providers first.
2. Alt F only if matrix fails.
3. Never put a BSC full/archive datadir on a failing or overloaded disk shared with other full nodes.

## Commands

```bash
# Probe eth_getProof capabilities (fill matrix)
python scripts/probe_eth_get_proof.py --rpc https://bsc-mainnet.public.blastapi.io

# Capture header fixtures (needs working RPC)
python scripts/capture_headers.py --rpc URL --out fixtures/mainnet/
```

## Demo Slice DoD

From a ≤24h multisource checkpoint: sync → Safe → verified `eth_getBalance(..., "latest")` succeeds in wallet mode (maps to Safe) with zero silent passthrough.

- [x] Multisource checkpoint (`verify-checkpoint` GATE PASS; age default 24h).
- [x] Header walk + `helios_bsc_syncStatus` (`safeLagBlocks` / `safeLagSeconds`, confirmation-depth, threshold 15).
- [x] Wallet `eth_getBalance(..., "latest")` → Safe, `eth_getProof` by number then hash.
- [x] `eth_blockNumber` → Safe height.
- [x] Zero silent passthrough (CI `helios-bsc-mock` + `Node::handle`).
- [x] Phase 0 gates (hardfork pin, epoch fixtures, appendix, proof matrix **partial**: Ankr number ≤~108 vs Safe 106–112).
- [x] ≥10 mainnet addresses vs **independent** oracle (live 2026-08-19: **19 unique / 214 compared / 0 mismatch**, Ankr vs BlastAPI, **≥1h** re-diff soak).
