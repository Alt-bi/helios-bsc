# helios-bsc

**A trust-minimized light client for BNB Smart Chain.** It serves a local JSON-RPC on
`127.0.0.1:8545` and answers wallet reads from proofs it verified itself against Parlia
consensus — so a lying upstream RPC produces an error, not a wrong balance. No chain
storage, no p2p, ~0 disk.

[Quickstart](docs/quickstart.md) · [What it verifies](docs/rpc-matrix.md) · [Threat model](docs/threat-model.md) · [All docs](docs/README.md)

---

## Why

When your wallet asks a public RPC for your balance, it believes the answer. There is no
proof involved and no way to tell a mistake from a lie. The alternative — running a full
BSC node — costs a multi-TB SSD and constant upkeep.

`helios-bsc` sits between the two. It uses an ordinary RPC endpoint as an **untrusted
data plane**: it asks for `eth_getProof` and headers, verifies the Parlia seals and the
Merkle-Patricia proofs locally, and serves the result. The upstream never has to be
trusted, only reachable.

## Install

Download the archive for your platform from the
[latest release](https://github.com/Alt-bi/helios-bsc/releases/latest), unpack it, and
verify the checksum:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

From source instead, if you have Rust:

```bash
cargo install --locked --git https://github.com/Alt-bi/helios-bsc helios-bsc
```

## Run

```bash
helios-bsc write-checkpoint --upstream https://bsc-rpc.publicnode.com --checkpoint-oracle https://bsc-dataseed.bnbchain.org --block latest --out checkpoint.json
helios-bsc run --upstream https://bsc-rpc.publicnode.com --checkpoint checkpoint.json
```

Then point MetaMask at `http://127.0.0.1:8545`, chainId **56**. Step-by-step, including
what each line of output means: **[docs/quickstart.md](docs/quickstart.md)**.

## What you get, and what you do not

| | |
|---|---|
| **Verified** | Balances, nonces, code, storage, `eth_call`, `eth_estimateGas`, headers, receipts, single-block logs — each checked against a state root this client walked to from your checkpoint |
| **Passed through** | `eth_sendRawTransaction` (broadcasting is not something a proof can cover), and opt-in fee oracles |
| **Refused** | Log *ranges*, filters, `eth_subscribe`, `debug_*`, `trace_*`, anything needing keys — `-32601`, never an unverified guess |
| **History** | ~112 blocks. This is not an archive node |
| **Audited** | No. See the [threat model](docs/threat-model.md) for what is and is not claimed |

Method-by-method detail: [docs/rpc-matrix.md](docs/rpc-matrix.md).

## How it works

1. A **checkpoint** fixes one block and the validator set sealing at it. Everything is
   verified relative to it, so it is written from two independent endpoints that agree.
2. Headers are walked forward, each one checked: ECDSA seal, in-turn difficulty,
   sealing-set membership, epoch activation, timing floors.
3. A **head** is chosen. By default that is the BEP-126 BLS-finalized head — the
   aggregate signature is verified against the epoch vote keys, ~2 blocks behind the tip.
   Without vote keys the client falls back to confirmation depth (15 distinct subsequent
   sealers, ~110 blocks) and says so on startup.
4. State reads fetch `eth_getProof` at that head and verify the Merkle-Patricia proof
   against the sealed `stateRoot`. An unproven value is an error, never a zero.

Depth: [design.md](docs/design.md) · [fast-finality.md](docs/fast-finality.md) · [consensus-appendix.md](docs/consensus-appendix.md)

## Status

MVP-2. The ≥24 h differential soak passed 2026-08-24 (24.06 h, exit 0), with 4 h on the
shipped build (2871 compared, 0 mismatch). A nightly soak runs in CI against live
mainnet. Full engineering record: [STATUS.md](STATUS.md).

**Not audited.** Use it to read, and read [SECURITY.md](SECURITY.md) before exposing it
to anything but loopback.

## Repo layout

```text
bin/helios-bsc/           # CLI
crates/
  helios-bsc-types/
  helios-bsc-config/      # fork schedule, chain constants
  helios-bsc-consensus/   # seals, epochs, snapshots, BLS finality
  helios-bsc-execution/   # MPT proofs, revm
  helios-bsc-rpc/         # method policy, wallet tags
  helios-bsc-mock/        # in-process lying upstream (CI, no network)
docs/                     # see docs/README.md
fixtures/mainnet/         # pinned headers
scripts/                  # proof probe, header capture, soak
```

## Prior art

| Project | Relation |
|---------|----------|
| [a16z/helios](https://github.com/a16z/helios) | Ethereum light client with local verified JSON-RPC. **Inspiration, not a fork** — BSC has Parlia, not sync committees, so none of the consensus layer ports across |
| [datachainlab/parlia-elc](https://github.com/datachainlab/parlia-elc) | Parlia light client for IBC/LCP bridges. Different product, useful consensus reference |
| Public BSC RPC providers | The blind-trust baseline this exists to replace. `helios-bsc` still needs one as a data plane, but verifies what it says |

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · MIT OR Apache-2.0
