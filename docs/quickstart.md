# Quickstart

Five minutes from nothing to a wallet reading balances it verified itself.

## What you are setting up

An ordinary RPC endpoint tells you your balance is 3 BNB and you believe it. helios-bsc
runs on your machine, asks that same endpoint for a **proof**, and checks the proof
against BNB Smart Chain's own consensus. A lying endpoint gets you an error, not a wrong
number.

It is **not a node**. No chain storage, no p2p, no mining. It sits in front of a normal
RPC and checks its answers. It needs that endpoint to be up.

## 1. Get the binary

Download the archive for your platform from the
[latest release](https://github.com/Alt-bi/helios-bsc/releases/latest) and unpack it.

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

Or build from source, if you have Rust:

```bash
cargo install --locked --git https://github.com/Alt-bi/helios-bsc helios-bsc
```

## 2. Write a checkpoint

The checkpoint is your starting point of trust: one block, and the validator set that
was sealing at it. Everything afterwards is checked against it, so it is worth getting
two independent endpoints to agree on it.

```bash
helios-bsc write-checkpoint --upstream https://bsc-rpc.publicnode.com --checkpoint-oracle https://bsc-dataseed.bnbchain.org --block latest --out checkpoint.json
```

```
oracle    bsc-dataseed.bnbchain.org agrees
epoch     118013000 active, turnLength=8
wrote checkpoint 118013907 hash=0xfd49e9d3… n_seal=21 fork=pasteur fastFinality=yes
```

`fastFinality=yes` means the file carries the BLS vote keys, so reads land ~2 blocks
behind the tip instead of ~110. Without a second endpoint the command still works and
warns; with one, a checkpoint they disagree on is never written.

A checkpoint goes stale in 24 h. Write a new one when you restart after a long gap.

## 3. Run it

```bash
helios-bsc run --upstream https://bsc-rpc.publicnode.com --checkpoint checkpoint.json
```

```
finality: fast (BEP-126 BLS finalized head, ~2 blocks behind the tip)
helios-bsc RPC on http://127.0.0.1:8545  (wallet mode: latest→Safe)
```

The first line says which rule is actually in force, not which one you asked for. If it
says `confirmation-depth` instead, the reason is on the same line.

Loopback only by default. `--allow-non-loopback` opens it to your LAN — there is no
authentication in the binary, so only do that behind something that has some.

## 4. Point a wallet at it

In MetaMask: **Settings → Networks → Add network manually**

| Field | Value |
|---|---|
| Network name | helios-bsc (verified) |
| RPC URL | `http://127.0.0.1:8545` |
| Chain ID | `56` |
| Currency symbol | `BNB` |

Balances, token balances and contract reads now come from proofs checked on your
machine.

## 5. Check it is doing its job

```bash
curl -s -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"helios_bsc_syncStatus"}' http://127.0.0.1:8545
```

The fields worth reading:

| Field | Meaning |
|---|---|
| `safeSource` | which rule chose the head — `fast-finality` or `confirmation-depth` |
| `lag` | how far behind the tip your reads are (2 is normal with fast finality) |
| `sealingSetEnforced` | `true` only when a checkpoint is loaded |
| `finalizedBlock` | the BLS-finalized head this client verified for itself |

## What it verifies, and what it does not

**Verified** — `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`,
`eth_getStorageAt`, `eth_getProof`, `eth_call`, `eth_estimateGas`, `eth_getBlockBy*`,
`eth_getBlockReceipts`, `eth_getLogs` and poll-based log filters over ranges up to 128
blocks. Each is checked against a state root
this client walked to from your checkpoint.

**Not verified** — `eth_sendRawTransaction` goes straight through, because broadcasting
is not something a proof can cover. Fee oracles (`eth_gasPrice`, `eth_feeHistory`) are
off by default and unverifiable when enabled.

**Refused** — `eth_subscribe` (this server is HTTP only), pending-transaction filters (no
mempool, and nothing unmined can be proven), `debug_*`, `trace_*`, `txpool_*`, and anything
needing keys: they return `-32601` rather than an unverified answer. `eth_getLogs` spans
wider than **128 blocks** are `-32602` — there is no log index here, so every block in a
range costs an upstream fetch and a `receiptsRoot` check.

**History** — reads reach back about 112 blocks. This is not an archive node.

Full method-by-method table: [rpc-matrix.md](./rpc-matrix.md).

## When something goes wrong

| Symptom | Cause |
|---|---|
| `waiting for a confirmation-depth head` | normal for a tip-fresh checkpoint; it resolves in under a minute |
| `checkpoint … is inside epoch …'s activation window` | write it at the block the message names |
| `provider window too shallow` | your endpoint will not serve proofs that far back; use one that does, or a checkpoint carrying vote keys so reads sit 2 blocks back |
| `-32001` on `eth_call` | something the call touched could not be proven, or it used a BSC-native precompile this client does not implement. Fail-closed by design |
| `-32601` | the method is refused, not broken. See the table above |

Deeper operational material: [slo.md](./slo.md), [checkpointing.md](./checkpointing.md),
[threat-model.md](./threat-model.md).
