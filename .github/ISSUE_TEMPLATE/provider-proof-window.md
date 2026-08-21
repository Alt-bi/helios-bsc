---
name: Provider proof window
about: eth_getProof lag vs Safe — do not weaken 15 sealers
labels: proof-window
---

**Provider host** (no API keys)


**Safe lag** (`helios_bsc_syncStatus.safeLagBlocks`, or tip − Safe)


**Proof result** (`inProofWindow`, error text, by number vs hash)


**Notes**

Live Safe lag is ~108–112. Fail-closed if lag > 112. Do **not** propose lowering Safe = 15 distinct subsequent sealers. Swap to a deeper proof RPC or self-hosted full/fast node.

See `docs/proof-provider-matrix.md` and `docs/runbooks/proof-fail-storm.md`.
