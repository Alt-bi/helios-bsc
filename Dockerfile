# helios-bsc — verified local JSON-RPC. Do not bake API keys into the image.
# Host publish must stay loopback (see compose.yaml). Optional checkpoint file only — no chain archive.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY bin ./bin
COPY crates ./crates
RUN cargo build --release --locked -p helios-bsc

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/helios-bsc /usr/local/bin/helios-bsc
USER nobody
EXPOSE 8545
ENTRYPOINT ["helios-bsc"]

# The failure a restart policy cannot see: the process is up, the port answers, and the
# head has not moved for an hour because the upstream went away or the sync wedged. The
# probe asks `helios_bsc_syncStatus`, which refreshes rather than answering out of stale
# state, and fails when the Safe head falls more than 5 minutes of chain behind the tip.
# Live confirmation-depth lag is ~48-50s, so that is roughly six times headroom -- see
# `helios-bsc health --help` for why the SLO bound would be the wrong threshold here.
#
# No curl in the image, and none added: the binary is already here and already links the
# HTTP client this needs.
#
# --start-period covers bootstrap. Walking from a checkpoint to the tip is a legitimate
# `-32003 not_synced`, and reading that as a stall would mark every start unhealthy.
#
# Docker does not restart an unhealthy container, and that is deliberate here: a client
# whose checkpoint has gone stale must not be restarted into the crash loop
# docs/runbooks/long-soak.md describes. This reports; a human decides.
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 CMD ["helios-bsc", "health", "--url", "http://127.0.0.1:8545"]
# 0.0.0.0 is required *inside* the container (Docker NAT is not loopback).
# Compose binds 127.0.0.1:8545 on the host. Do not publish 0.0.0.0 without a proxy.
CMD ["run", "--listen", "0.0.0.0:8545", "--allow-non-loopback"]
