# ============================================================
# Étape 1 — Build
# ============================================================
FROM rust:1.85-slim AS builder

WORKDIR /build

# Copier le workspace complet
COPY Cargo.toml Cargo.lock ./
COPY llm-common/ llm-common/
COPY llm-manager/ llm-manager/
COPY llm-decision/ llm-decision/

# Compiler uniquement llm-decision en mode release
RUN cargo build --release -p llm-decision

# ============================================================
# Étape 2 — Image finale
# ============================================================
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/llm-decision /usr/local/bin/llm-decision

# Variables d'environnement par défaut (surchargées par Kubernetes ConfigMap)
ENV OLLAMA_BASE_URL=http://localhost:11434
ENV QUARANTINE_PATH=/quarantaine
ENV DECISION_PORT=3002
ENV MANAGER_PORT=3003

EXPOSE 3002

ENTRYPOINT ["/usr/local/bin/llm-decision"]
