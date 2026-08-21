## What


## Checklist

- [ ] `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all`
- [ ] Fail-closed: no silent RPC passthrough; unsupported methods stay `-32601`
- [ ] No `.env`, API keys, or key-bearing URLs
- [ ] Safe = 15 distinct subsequent sealers is not weakened
- [ ] `eth_call` not added (MVP-2)
