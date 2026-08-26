# Deploy (Docker)

The binary has **no RPC auth**. The host must publish loopback only.

## From the published image

Released tags are pushed to the GitHub Container Registry for `linux/amd64` and
`linux/arm64`, so nothing is built locally:

```bash
docker run --rm -p 127.0.0.1:8545:8545 ghcr.io/alt-bi/helios-bsc:latest run --upstream https://bsc-rpc.publicnode.com --listen 0.0.0.0:8545 --allow-non-loopback
```

`--listen 0.0.0.0` is what the process binds **inside** the container, where Docker NAT is
not loopback. `-p 127.0.0.1:8545:8545` is what makes that safe: the port reaches the host
on loopback only. Publish it as `-p 8545:8545` and the process answers every interface
with no authentication in front of it.

`:latest` follows the newest release. Pin `ghcr.io/alt-bi/helios-bsc:0.2.0` for anything
you want to stay put. Images are built from source at the tag with `--locked`, on a native
runner per architecture.

## From source, with compose

```bash
cp .env.example .env   # set HELIOS_BSC_UPSTREAM; do not commit .env
docker compose up --build -d
# local wallet RPC: http://127.0.0.1:8545
```

Compose maps `127.0.0.1:8545:8545`. Changing that to `8545:8545` exposes the process on every interface — use a reverse proxy + firewall, and keep `--allow-non-loopback` as an explicit choice.

Inside the container the process listens on `0.0.0.0` because Docker NAT is not loopback. That is not a host bind.

No chain archive is required. Optional: persist only `checkpoint.json` on a small local volume. Do **not** place a multi-TB BSC full/archive node datadir next to unrelated heavy node storage without planning disk and I/O separately.

```bash
docker compose run --rm helios-bsc doctor
docker compose run --rm helios-bsc probe-safe --oracle https://bsc-mainnet.public.blastapi.io
```

## Is it actually working?

A container can be up, answering on its port, and stalled — the upstream went away, or the
sync wedged — and nothing you would normally look at says so. `restart: unless-stopped`
only sees a process that exited. `/metrics` reads counters and a lock-free head snapshot,
so it keeps reporting the last thing that worked. The port accepts connections regardless.

The image ships a `HEALTHCHECK` that asks the one question none of those answer:

```bash
docker compose ps
```

`healthy` means the Safe head is moving. `unhealthy` means it has fallen more than five
minutes of chain behind the tip, or the client cannot verify a head at all. The reason is
kept:

```bash
docker inspect --format '{{json .State.Health}}' <container> | jq -r '.Log[-1].Output'
```

You can run the same probe by hand, in or out of a container:

```bash
helios-bsc health                       # exit 0 healthy, 1 not
helios-bsc health --max-lag-seconds 60  # stricter
```

Three things worth knowing about it:

- **It reports; it does not restart.** Docker does not restart an unhealthy container on
  its own, and that is wanted here: a client refusing to start because its checkpoint went
  stale must not be restarted into a loop. See
  [runbooks/long-soak.md](runbooks/long-soak.md).
- **Five minutes is not the SLO.** [slo.md](slo.md) puts the in-turn upper bound at 120
  blocks (~54 s) and says a longer stretch is a valid out-of-turn run, not a failure.
  Gating on the SLO would paint a working client red; a probe that is normally red gets
  switched off. A genuinely stalled head does not hover — at 450 ms blocks it grows by
  8000 blocks an hour — so the wide threshold costs nothing in detection.
- **Startup is not a stall.** Walking from a checkpoint to the tip answers `-32003`
  legitimately, so the healthcheck has a 120 s `--start-period`. A checkpoint far behind
  the tip can need longer; raise it rather than reading the first minutes as a fault.

## What compose takes away from the container

`compose.yaml` runs the service with no capabilities, a read-only root filesystem, a small
in-memory `/tmp`, and `no-new-privileges`. None of it is a trade-off here: the process
binds a high port as `nobody`, makes outbound HTTPS, and writes exactly one file — the
checkpoint store, on the volume you mount for it. Every one of those four is asserted in
CI, because a setting that costs nothing is a setting a later edit drops without anything
appearing to break.

This matters more in a container than anywhere else. [threat-model.md](threat-model.md)
names it as the one path where both in-process guards are inactive by construction: the
process must bind `0.0.0.0` inside, so the loopback `Host` check does not apply and
`--allow-non-loopback` is already set for you. What is left protecting the endpoint is
your own `-p 127.0.0.1:` prefix — and, if something does get in, how little the container
gives them.
