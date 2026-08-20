# helios-bsc

**Trust-minimized Parlia light client** for BNB Smart Chain — local verified JSON-RPC, ~0 chain storage.

Inspired by [a16z/helios](https://github.com/a16z/helios) for Ethereum. BSC has **no sync committees**; consensus is **Parlia** (ECDSA seals, epoch validator sets). This is a **greenfield** project (not a Helios fork).

| | |
|--|--|
| **Status** | **Demo Slice** — seals + Safe + MPT; local RPC `helios-bsc run` (header-verified `eth_getBlock*`) |
| **License** | MIT OR Apache-2.0 |
| **Design** | [docs/design.md](docs/design.md) · [RPC matrix](docs/rpc-matrix.md) · [wallet guide](docs/wallet-guide.md) · [checkpoints](docs/checkpointing.md) · [SLOs](docs/slo.md) · [threat model](docs/threat-model.md) |
| **Chain** | BSC mainnet (`chainId` 56) |

## Why

Blind public RPCs lie. Full BSC nodes need multi-TB SSD. `helios-bsc` aims for:

- local `:8545`-style RPC
- cryptographically **verified** balances / storage against a Safe `stateRoot`
- wallet mode: `latest` → Safe (~1–2 min lag)
- still uses upstream only as **untrusted data plane** (`eth_getProof` by hash/number)

## Repo layout

```text
helios-bsc/
  bin/helios-bsc/           # CLI
  crates/
    helios-bsc-types/
    helios-bsc-config/
    helios-bsc-consensus/   # seals / epochs / confirmation-depth
    helios-bsc-execution/   # MPT eth_getProof
    helios-bsc-rpc/         # method policy + wallet tags
    helios-bsc-mock/        # in-process lying upstream (CI, no network)
  docs/                     # design + Phase 0 gates
  fixtures/mainnet/
  scripts/                  # proof probe, header capture, soak vs oracle
```

## Quick start

```bash
cd helios-bsc
cargo test --workspace   # includes lying-RPC mock through Node::handle
cargo run -p helios-bsc -- info
cargo run -p helios-bsc -- doctor   # env hosts only, never API keys; Pasteur countdown

# Walk recent headers, compute newest Safe, fetch eth_getProof
# Windows: set HELIOS_BSC_UPSTREAM to your BSC HTTPS JSON-RPC (see .env.example)
cargo run -p helios-bsc -- probe-safe --upstream %HELIOS_BSC_UPSTREAM% --oracle https://bsc-mainnet.public.blastapi.io
cargo run -p helios-bsc -- run --listen 127.0.0.1:8545
# Optional transport failover (still untrusted): --backup $HELIOS_BSC_BACKUP

# Optional: sealing-set membership (does not invent validators from recent miners)
cargo run -p helios-bsc -- write-checkpoint --block 0x… --sealing-set 0xabc,0xdef,… --out checkpoint.json
# or: --sealing-set-from-epoch 0x…  (activated epoch extraData; fail-closed before E+87)
cargo run -p helios-bsc -- verify-checkpoint --checkpoint checkpoint.json
cargo run -p helios-bsc -- run --checkpoint checkpoint.json --require-checkpoint --listen 127.0.0.1:8545
# LAN bind (no RPC auth in-process): --allow-non-loopback --listen 0.0.0.0:8545
# Wallet send loop (receipts header-bound to Safe; gasPrice unbound): --allow-unverified-passthrough
# Restart reuses the last verified header written back to checkpoint.json
# (--checkpoint-store other.json or --no-checkpoint-store to override)
# Default --max-sync 16000 (~2h of 0.45s blocks). --lookback 130 is only the
# no-checkpoint Safe window (~1 min) — too short for a restart by itself.

# Second source must agree on checkpoint hash/number/stateRoot (not the same RPC host)
cargo run -p helios-bsc -- run --checkpoint checkpoint.json \
  --require-multisource-checkpoint \
  --checkpoint-oracle https://bsc-mainnet.public.blastapi.io
```

Docker (host loopback only; key stays in `.env`, not the image):

```bash
cp .env.example .env
docker compose up --build -d    # http://127.0.0.1:8545
```

See [docs/deploy.md](docs/deploy.md). Do not publish `0.0.0.0:8545` without a reverse proxy and auth. This client stores almost no chain data — do **not** co-locate a BSC full/archive node on a disk you already use for other heavy node datadirs.

Wallet mode: `eth_blockNumber` and proof-backed `latest` map to **Safe**. Verified: `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`, header-only `eth_getBlockByNumber` / `eth_getBlockByHash` (at or below Safe). `eth_sendRawTransaction` is **unverified broadcast**. Many free RPC providers prune `eth_getProof` state before Safe lag (~110 blocks) — fail-closed if the upstream cannot prove Safe; use a deeper provider or self-hosted full/fast node as the untrusted data plane.

`--checkpoint FILE` enables sealing-set membership (unauthorized sealers rejected). Without it, lookback only checks ECDSA coinbase + parent links. Checkpoint age default **24h** (`--allow-stale-checkpoint` to override). The sealing set is operator-supplied — never inferred from miners in the lookback window.

Soak vs an independent oracle (not the proof upstream):

```bash
# MPT-verified, no local RPC server. Retries skipped addresses after recatch.
# Demo Slice gate: --min-unique 10. Stretch 1h: --duration-secs 3600
cargo run -p helios-bsc -- soak --oracle https://bsc-mainnet.public.blastapi.io --once --min-unique 10

# or loop a running helios-bsc RPC
python scripts/soak_vs_oracle.py --once
```

## Roadmap (short)

1. **Phase 0** — hardfork pin, fixtures, proof provider matrix (hash/number or Alt F)
2. **Demo Slice** — checkpoint → seals → Safe → verified `eth_getBalance`
3. **MVP-1** — more verified reads + unverified `eth_sendRawTransaction`
4. **MVP-2** — Fast Finality (if RPC exposes votes), constrained `eth_call`

Honest calendar: **months** of part-time work, not a weekend. See design doc.

## Deploy note

Default bind is loopback (`127.0.0.1:8545`). For LAN/VPN exposure use a reverse proxy with authentication — the binary itself has no RPC auth.

## Prior art

| Project | Relation |
|---------|----------|
| [a16z/helios](https://github.com/a16z/helios) | Ethereum (+ OP Stack / Linea) light client with local verified JSON-RPC. **Inspiration** — not a fork. BSC has **Parlia**, not ETH sync committees. |
| [datachainlab/parlia-elc](https://github.com/datachainlab/parlia-elc) | Parlia light client for **IBC / LCP bridges** (ELC), not a wallet-local `:8545` RPC. Different product; useful consensus reference. |
| Public BSC RPC providers | Blind-trust data plane. `helios-bsc` still needs an upstream for headers/proofs but **verifies** seals + MPT. |

## Community

Independent open-source track (MIT OR Apache-2.0). Optional discussion with Helios maintainers only **after** a solid public Demo Slice.

