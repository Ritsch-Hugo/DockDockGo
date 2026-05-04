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

COPY --from=builder /app/target/release/dockdockgo-orchestrator /app/dockdockgo-orchestrator

RUN chown -R appuser:appuser /app

USER appuser
EXPOSE 3000

ENV DATABASE_URL=""
ENV BIND_ADDR="0.0.0.0:3000"
ENV HIGH_LEVEL_URL="http://127.0.0.1:4000/v1/high-level"
ENV LLM_DECISION_URL="http://127.0.0.1:5000/v1/decision"
ENV RUST_LOG="info"

CMD ["/app/dockdockgo-orchestrator"]
