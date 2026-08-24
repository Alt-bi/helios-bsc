# helios-bsc

**Trust-minimized Parlia light client** for BNB Smart Chain — local verified JSON-RPC, ~0 chain storage.

Inspired by [a16z/helios](https://github.com/a16z/helios) for Ethereum. BSC has **no sync committees**; consensus is **Parlia** (ECDSA seals, epoch validator sets). This is a **greenfield** project (not a Helios fork).

| | |
|--|--|
| **Status** | **Demo Slice closed.** 1h re-diff soak GATE PASS (2026-08-19). **24h soak** is still the MVP-1 GA live gate; the longest clean run so far is **13.9h** (compared=4129, mismatch=0), ended by the host, not by the client. |
| **Repo** | https://github.com/Alt-bi/helios-bsc |
| **License** | MIT OR Apache-2.0 |
| **Design** | [docs/design.md](docs/design.md) · [RPC matrix](docs/rpc-matrix.md) · [wallet guide](docs/wallet-guide.md) · [checkpoints](docs/checkpointing.md) · [fast finality](docs/fast-finality.md) · [SLOs](docs/slo.md) · [threat model](docs/threat-model.md) |
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
# Optional Prometheus metrics on GET /metrics (off by default): --metrics
# Optional BEP-126 BLS finality for latest/safe/finalized (~2 blocks behind tip
# instead of ~110). Falls back to confirmation depth when no finalized head is
# known. Needs a checkpoint written with --sealing-set-from-epoch (vote keys):
#   --finality fast

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

**Free public RPC is enough with `--finality fast`.** The BLS-finalized head sits ~2 blocks behind the tip instead of ~110, so a provider only needs a ~3-block `eth_getProof` window rather than ~112. Verified live 2026-08-21 against the keyless `bsc-mainnet.public.blastapi.io`: `eth_getBalance` / `eth_getStorageAt` / `eth_call` all MPT-verified, and 8 addresses matched two independent oracles with 0 mismatches. Needs a checkpoint written with `--sealing-set-from-epoch` (it carries the BLS vote keys). Tag-only providers still cannot serve proofs at all. See [docs/fast-finality.md](docs/fast-finality.md).

Wallet mode: `eth_blockNumber` and proof-backed `latest` map to **Safe**. Verified: `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`, constrained `eth_call` (Safe only; `to` + optional `data`; revm + iterative proofs; unproven SLOAD/account → `-32001`; gas cap 50_000_000; max 8 proof rounds; no state overrides; no create), best-effort `eth_estimateGas` (same proof-backed path; never proxied; gas is not consensus), header-only `eth_getBlockByNumber` / `eth_getBlockByHash` (at or below Safe). `eth_sendRawTransaction` is **unverified broadcast**. Many free RPC providers prune `eth_getProof` state before Safe lag (~110 blocks) — fail-closed if the upstream cannot prove Safe; use a deeper provider or self-hosted full/fast node as the untrusted data plane.

`--checkpoint FILE` enables sealing-set membership (unauthorized sealers rejected). Without it, lookback only checks ECDSA coinbase + parent links. Checkpoint age default **24h** (`--allow-stale-checkpoint` to override). The sealing set is operator-supplied — never inferred from miners in the lookback window.

Soak vs an independent oracle (not the proof upstream):

```bash
# MPT-verified, no local RPC server. Retries skipped addresses after recatch.
# Demo Slice gate: --min-unique 10. 1h re-diff closed 2026-08-19; 24h still for GA.
cargo run -p helios-bsc -- soak --oracle https://bsc-mainnet.public.blastapi.io --once --min-unique 10

# The GA gate. --state accumulates soak time across sessions, so a host that dies at
# hour 14 resumes instead of restarting the clock; re-run the same command to continue;
# it is saved after every burst, not once a round.
#
# With --finality fast the oracle must serve the parlia_ namespace: the run cross-checks
# this client's justified/finalized pair against geth's own answer, and fails closed if
# that check never produced a verdict. Most public BSC endpoints answer -32601 for it;
# bsc-rpc.publicnode.com serves it, which is why it is the oracle here.
cargo run --release -p helios-bsc -- soak   --upstream https://bsc-mainnet.public.blastapi.io   --oracle https://bsc-rpc.publicnode.com   --checkpoint checkpoint.json --finality fast   --duration-secs 86400 --state soak-state.json

# or loop a running helios-bsc RPC
python scripts/soak_vs_oracle.py --once
```

## Roadmap (short)

1. **Phase 0** — **done** (hardfork pin, epoch fixtures, proof provider matrix)
2. **Demo Slice** — **closed** (checkpoint → seals → Safe → verified `eth_getBalance`; 1h re-diff soak GATE PASS 2026-08-19: unique=19, compared=214, match=214, mismatch=0, skip=38)
3. **MVP-1** — verified nonce/code/storageAt + unverified `eth_sendRawTransaction` **in tree**; **≥24h soak still the GA live gate**. Header verification is now complete against the pinned v1.7.8 rules: out-of-turn backoff, Maxwell FF recents prune and `baseFeePerGas` all closed (BSC has no parent `baseFee` formula — `CalcBaseFee` returns a constant `0` on any Parlia chain).
4. **MVP-2** — constrained `eth_call` + best-effort `eth_estimateGas` (proof-backed revm; never proxied). **Fast Finality (BLS) implemented** — vote attestations decoded and their aggregate BLS signature verified against the epoch vote keys; live mainnet finalized lag **2 blocks** vs 106–112 for confirmation depth ([docs/fast-finality.md](docs/fast-finality.md)). The `finalized` tag still resolves to the confirmation-depth Safe head — moving it wants its own soak.

Honest calendar: **months** of part-time work, not a weekend. See design doc. Pasteur (2026-08-25) is scheduled, not live.

## Deploy note

Default bind is loopback (`127.0.0.1:8545`). For LAN/VPN exposure use a reverse proxy with authentication — the binary itself has no RPC auth.

## Prior art

| Project | Relation |
|---------|----------|
| [a16z/helios](https://github.com/a16z/helios) | Ethereum (+ OP Stack / Linea) light client with local verified JSON-RPC. **Inspiration** — not a fork. BSC has **Parlia**, not ETH sync committees. |
| [datachainlab/parlia-elc](https://github.com/datachainlab/parlia-elc) | Parlia light client for **IBC / LCP bridges** (ELC), not a wallet-local `:8545` RPC. Different product; useful consensus reference. |
| Public BSC RPC providers | Blind-trust data plane. `helios-bsc` still needs an upstream for headers/proofs but **verifies** seals + MPT. |

## Community

Public repo: [github.com/Alt-bi/helios-bsc](https://github.com/Alt-bi/helios-bsc) (MIT OR Apache-2.0). See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Optional discussion with Helios maintainers only **after** a solid public Demo Slice.

