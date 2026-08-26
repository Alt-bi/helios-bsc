# Deploy (Docker)

The binary has **no RPC auth**. The host must publish loopback only.

## From the published image

Released tags are pushed to the GitHub Container Registry for `linux/amd64` and
`linux/arm64`, so nothing is built locally:

```bash
docker run --rm -p 127.0.0.1:8545:8545 ghcr.io/alt-bi/helios-bsc:latest run --upstream https://bsc-mainnet.public.blastapi.io --listen 0.0.0.0:8545 --allow-non-loopback
```

The upstream must serve `eth_getProof` at a *named block*, not only for the tag
`latest` — see [proof-provider-matrix.md](proof-provider-matrix.md), and the startup
probe that tells you when it does not.

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
