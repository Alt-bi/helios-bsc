# Documentation

Organised by what you came here to do.

## I want to run it

| | |
|---|---|
| [quickstart.md](quickstart.md) | Binary to a wallet reading verified balances. **Start here.** |
| [checkpointing.md](checkpointing.md) | What a checkpoint is, how to write one, why two sources matter, when it goes stale |
| [deploy.md](deploy.md) | Docker, and the rules for binding anywhere but loopback |
| [slo.md](slo.md) | What "working" looks like — lag targets, Prometheus metrics, what to alert on |
| [runbooks/proof-fail-storm.md](runbooks/proof-fail-storm.md) | When proofs start failing: what to check, in order, and what not to do |
| [runbooks/long-soak.md](runbooks/long-soak.md) | Running a soak for days or a month: outage tolerance, the two limits that end a run, and how to read the result |

## I want to know what to trust

| | |
|---|---|
| [rpc-matrix.md](rpc-matrix.md) | Every method: verified, passed through, or refused — with the exact constraints on each |
| [threat-model.md](threat-model.md) | Each attack a lying upstream can attempt, and what stops it |
| [fast-finality.md](fast-finality.md) | BEP-126 BLS finality: wire format, verification rules, and why it is what makes free public RPC usable |

## I want to work on it

| | |
|---|---|
| [design.md](design.md) | The full design document — architecture, goals, non-goals, acceptance criteria |
| [consensus-appendix.md](consensus-appendix.md) | Normative pins into geth's `parlia.go` / `snapshot.go`, with pseudo-code |
| [hardfork-table.md](hardfork-table.md) | Fork schedule and Parlia constants, pinned to a `bnb-chain/bsc` commit |
| [proof-provider-matrix.md](proof-provider-matrix.md) | Which RPC providers can actually serve `eth_getProof`, measured |
| [../fixtures/mainnet/README.md](../fixtures/mainnet/README.md) | The pinned mainnet headers and signed envelopes the test suite runs against, and how to capture more |

| [engineering-log.md](engineering-log.md) | How each non-obvious item was found, closed and checked — the maintainer's record |

Also: [STATUS.md](../STATUS.md) for where the project is today, and
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Conventions in these docs

**Fail-closed** means an error rather than an unverified answer. It is the default
everywhere; where something is *not* verified, the docs say so in the same sentence.

**Safe** is the confirmation-depth head: the newest block with ≥15 distinct subsequent
sealers, ~110 blocks behind the tip. **Finalized** is the BEP-126 BLS-finalized head,
~2 blocks behind. Since 2026-08-25 block tags resolve to the latter by default and fall
back to the former; the startup line names which rule is in force.

Measurements carry the date they were taken. A number without one is a constant from
pinned source, not an observation.
