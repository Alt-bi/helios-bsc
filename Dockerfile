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
# 0.0.0.0 is required *inside* the container (Docker NAT is not loopback).
# Compose binds 127.0.0.1:8545 on the host. Do not publish 0.0.0.0 without a proxy.
CMD ["run", "--listen", "0.0.0.0:8545", "--allow-non-loopback"]
