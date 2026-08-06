# syntax=docker/dockerfile:1
# sentryd — multi-stage Rust build + Python mesh sidecar

# ── Stage 1: Build sentryd Rust binary ──────────────────────────
FROM rust:1.81-slim-bookworm AS builder

WORKDIR /build
COPY sentryd/ .
RUN apt-get update && apt-get install -y pkg-config libsqlite3-dev && rm -rf /var/lib/apt/lists/*
RUN cargo build --release --bin sentryd

# ── Stage 2: Runtime image ──────────────────────────────────────
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# sentryd binary
COPY --from=builder /build/target/release/sentryd /usr/local/bin/sentryd

# Python mesh sidecar + deps
COPY scripts/mesh-discover.py /app/scripts/mesh-discover.py
COPY sentryd/config/sentryd.yaml /etc/sentryd/sentryd.yaml

RUN pip install --no-cache-dir pyyaml websockets pynacl

# TUN device
RUN mkdir -p /dev/net && mknod /dev/net/tun c 10 200 2>/dev/null || true

EXPOSE 514/udp

ENTRYPOINT ["python3", "/app/scripts/mesh-discover.py"]
CMD ["sentryd", "daemon"]
