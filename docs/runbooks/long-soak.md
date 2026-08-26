# Long unattended soak (days to a month)

A 45-minute CI soak and a 30-day soak fail in different ways. The short one asks *is the
client right?* — and any interruption should stop it loudly. The long one asks *does it
stay right?*, and over that span the client **will** restart at least once: a reboot, a
container restart, a checkpoint refresh. A run that stops at the first blip reports on its
first three days and tells you nothing about the other twenty-seven.

That difference is a flag, not a guess.

## Start it

```bash
python scripts/soak_vs_oracle.py \
  --local http://127.0.0.1:8545 \
  --oracle https://bsc-rpc.publicnode.com \
  --rounds 43200 --interval 60 \
  --max-local-outage 900
```

`--rounds 43200 --interval 60` is roughly 30 days. `--max-local-outage 900` lets the client
be unreachable for up to 15 minutes in one stretch before the run gives up.

**`--max-local-outage` tolerates transport failures only.** A verification mismatch ends
the run immediately and always — that is the finding the whole exercise exists to catch,
and it is never waited out. The default is `0`, which is the old behaviour: stop at the
first local error. Do not set it in CI.

Outages are never silent. Each one prints as it happens and all of them land in the
summary:

```
  LOCAL_DOWN   helios_bsc_syncStatus: <urlopen error ...>  (waiting, 60s of 900s)
  LOCAL_BACK   recovered after 184s
# SUMMARY  compared=… match=… mismatch=0 skip=…  outages=1 outage_rounds=3 longest_outage=184s
```

A summary with `outages=` is a run that limped. It is still a valid result — but read it as
"twenty-nine days of coverage and one gap", not as thirty clean days.

## The two cliffs that end a run

Both are correct fail-closed behaviour. Both bite an unattended host.

| Limit | Default | What happens |
|---|---|---|
| `--max-sync` | 16,000 blocks ≈ **2 hours** of chain | The client refuses to start: *"checkpoint is N blocks behind tip (limit 16000) — fail-closed (fresher checkpoint)"* |
| `--max-checkpoint-age-hours` | **24** | The client refuses to start: *"checkpoint age Ns exceeds max Ns — fail-closed (refresh checkpoint)"* |

So the downtime budget for an unattended host is about **two hours**. Past that, the
process cannot resume from its stored checkpoint and needs a new one.

**This matters because `compose.yaml` sets `restart: unless-stopped`.** A client that
refuses to start is restarted, refuses again, and loops. `docker compose ps` shows
`Restarting`, which is visible only if somebody looks — and nobody looks for thirty days.
The soak is what notices: it reports `LOCAL_DOWN`, then exits non-zero once
`--max-local-outage` is exceeded.

### Recovery

```bash
helios-bsc write-checkpoint \
  --upstream https://bsc-rpc.publicnode.com \
  --checkpoint-oracle https://bsc-dataseed.bnbchain.org \
  --block latest --out checkpoint.json
```

Two independent endpoints must agree on the header before it becomes a root of trust.
Then restart the client and start a fresh soak run.

**Do not** reach for `--allow-stale-checkpoint` to get past this. It exists for a
deliberate offline exercise, not for unattended recovery: it accepts a root of trust whose
freshness nobody checked, which is the one assumption everything else in this client is
built on.

## Before you start a month-long run

- [ ] Write a fresh checkpoint. The 24-hour clock starts from its timestamp, not from the run.
- [ ] Confirm the oracle is a **different host** from `--upstream` and from `--backup`. Comparing a client against the process that fed it proves nothing.
- [ ] Confirm the oracle serves `parlia_*` if you run `--finality fast`; most public endpoints answer `-32601`. `bsc-rpc.publicnode.com` serves it.
- [ ] Redirect output to a file and rotate it. Thirty days of round summaries is not large, but an unrotated log on a small VPS is a way to fill a disk.
- [ ] Decide the downtime policy. `restart: unless-stopped` plus a two-hour budget means an outage longer than that needs a human.

## Reading the result

| Summary | Meaning |
|---|---|
| `mismatch=0`, no `outages=` | Clean. The claim is the full span |
| `mismatch=0`, `outages=N` | Valid, with gaps. Report the span minus the gaps |
| `mismatch>0` | **Incident.** The run stopped there on purpose. This is a verification failure, not an operational one — see [proof-fail-storm.md](proof-fail-storm.md) and treat the mismatching field as the finding |
| `local_err=…` | The client was unreachable past the tolerance. Operational, not a verification result — nothing is proven or disproven about correctness |
| `compared=0` | Fail-closed: nothing was actually checked. Never report this as a pass |

## What a long soak does not prove

It exercises the read path against one independent node, on one host, against whatever the
chain did that month. It is not an audit, it does not explore adversarial inputs — that is
what `helios-bsc-mock` and the adversarial suite are for — and a month without a mismatch
is evidence, not proof. See [threat-model.md](../threat-model.md) for what is and is not
claimed.
