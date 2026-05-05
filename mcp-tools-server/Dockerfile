# ============================================================
# Étape 1 — Build
# ============================================================
FROM rust:1.88-slim AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release -p mcp-tools-server

# ============================================================
# Étape 2 — Image finale
# ============================================================
FROM gcr.io/distroless/cc-debian12

COPY --from=builder /build/target/release/mcp-tools-server /usr/local/bin/mcp-tools-server

ENV MCP_SERVER_PORT=3004
ENV STATIC_SCANNER_URL=http://localhost:3002
ENV COMPLIANCE_SCANNER_URL=http://localhost:3001

EXPOSE 3004

ENTRYPOINT ["/usr/local/bin/mcp-tools-server"]
