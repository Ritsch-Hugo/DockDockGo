# ---------- Build stage ----------
FROM rust:1.88-bookworm AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates build-essential pkg-config \
 && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release

# ---------- Runtime stage ----------
FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 10001 appuser

COPY --from=builder /app/target/release/docker-mitm /app/docker-mitm

RUN mkdir -p /app/certs-mitm /app/cache /app/quarantaine \
 && chown -R appuser:appuser /app

VOLUME ["/app/certs-mitm", "/app/cache", "/app/quarantaine"]

USER appuser
EXPOSE 8443
CMD ["/app/docker-mitm"]
