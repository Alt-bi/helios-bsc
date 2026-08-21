# Contributing

PRs must stay **fail-closed**. This is a Parlia light client, not an RPC proxy.

## Build

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

CI runs the same (`cargo fmt --all -- --check`). Toolchain is stable (`rust-toolchain.toml`); MSRV is **1.80**.

## Secrets and disks

- Never commit `.env`, API keys, or URLs that embed keys. Copy `.env.example`. `helios-bsc doctor` prints hosts only.
- Never put a BSC full/archive node datadir on a disk already used for other heavy nodes (I/O and space collide). This client stores almost no chain data.

## Product constraints (not style nits)

- No silent RPC passthrough. Unsupported methods stay `-32601`.
- Do not weaken Safe = **15** distinct subsequent sealers (`floor(2N/3)+1`). A shallow `eth_getProof` window is a provider issue — swap the RPC, do not change consensus.
- `eth_call` is **MVP-2**. Do not add it in drive-by PRs.

See [`docs/design.md`](docs/design.md), [`docs/rpc-matrix.md`](docs/rpc-matrix.md), [`docs/threat-model.md`](docs/threat-model.md).
