# helios-bsc — One-pager (BNB Chain Builder Grant)

**Project:** helios-bsc  
**Category:** Developer Tools & Infrastructure  
**License:** MIT OR Apache-2.0  
**Ask:** **USD 8,000**  
**Team:** Solo developer  
**Repo:** `https://github.com/Alt-bi/helios-bsc` _(replace)_  
**Chain:** BNB Smart Chain (chainId **56**, Parlia)

## Problem

Applications and wallets on BSC typically send `eth_*` JSON-RPC to centralized providers. A malicious or buggy RPC can lie about balances, storage, and call results. Running a full/fast BSC node requires multi-terabyte SSD and continuous ops — impractical for most users and small teams. Ethereum already has [Helios](https://github.com/a16z/helios); **BSC has no equivalent wallet-grade local verified RPC** (Parlia ≠ ETH sync committees).

## Solution

**helios-bsc** is a Rust **Parlia light client** that:

- Walks recent headers, verifies **ECDSA seals**, epoch validator transitions, and **confirmation-depth Safe** head (≥15 distinct sealers).
- Verifies account/storage via **`eth_getProof` MPT** against the Safe `stateRoot`.
- Serves a **local fail-closed JSON-RPC** (wallet mode: `latest` → Safe): balances, nonce, code, storage, header-only blocks; unverified `eth_sendRawTransaction` broadcast.
- Uses ~**0 durable chain storage** (checkpoint + ephemeral headers). Upstream is an **untrusted data plane**.

## Status (traction)

- Working **Demo Slice**: seals, Safe, MPT, local RPC, checkpoints with sealing-set membership, adversarial mock tests, soak vs independent oracle.
- Pinned to `bnb-chain/bsc` **v1.7.8**; live params: epochLength 1000, turnLength 8, N_seal 21.
- Limitation (documented): many free RPCs prune proofs before Safe lag (~108–112 blocks). Grant funds closing this ops gap (paid/archive path or Alt F runbook) and public packaging.

## Differentiation

| Prior art | Why not enough |
|-----------|----------------|
| a16z Helios | Ethereum / L2 — not Parlia |
| datachainlab/parlia-elc | IBC/LCP bridge light client — not local wallet `:8545` |
| Public RPC SaaS | Speed/SLA — not cryptographic verification of reads |

## Ask & use of funds ($8,000)

See `milestones.md`. Equity-free grant for open-source public goods on BNB Chain.

## Contact

- Email: _(fill)_  
- Telegram: _(fill)_  
- GitHub: _(fill)_
