# Deploy (Docker)

The binary has **no RPC auth**. The host must publish loopback only.

```bash
cp .env.example .env   # set HELIOS_BSC_UPSTREAM; do not commit .env
docker compose up --build -d
# local wallet RPC: http://127.0.0.1:8545
```

Compose maps `127.0.0.1:8545:8545`. Changing that to `8545:8545` exposes the process on every interface — use a reverse proxy + firewall, and keep `--allow-non-loopback` as an explicit choice.

Inside the container the process listens on `0.0.0.0` because Docker NAT is not loopback. That is not a host bind.

No chain archive. Do not put anything on `/mnt/big`. Optional later: small volume on `/mnt/fast` for `checkpoint.json` only.

```bash
docker compose run --rm helios-bsc doctor
docker compose run --rm helios-bsc probe-safe --oracle https://bsc-mainnet.public.blastapi.io
```
