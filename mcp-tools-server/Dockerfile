# ============================================================
# Étape 1 — Build
# ============================================================
FROM rust:1.85-slim AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release -p mcp-tools-server

# ============================================================
# Étape 2 — Image finale
# ============================================================
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/mcp-tools-server /usr/local/bin/mcp-tools-server

ENV MCP_SERVER_PORT=3004
ENV STATIC_SCANNER_URL=http://localhost:3002
ENV COMPLIANCE_SCANNER_URL=http://localhost:3001

EXPOSE 3004

ENTRYPOINT ["/usr/local/bin/mcp-tools-server"]
