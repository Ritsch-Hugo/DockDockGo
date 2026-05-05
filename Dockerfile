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

COPY --from=builder /app/target/release/dockdockgo-mcp-llm /app/dockdockgo-mcp-llm

RUN chown -R appuser:appuser /app

USER appuser
EXPOSE 4000

ENV GEMINI_API_KEY=""
ENV BIND_ADDR="0.0.0.0:4000"
ENV RUST_LOG="info"

CMD ["/app/dockdockgo-mcp-llm"]
