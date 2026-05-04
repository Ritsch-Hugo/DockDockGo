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
FROM gcr.io/distroless/cc-debian12

COPY --from=builder /build/target/release/llm-decision /usr/local/bin/llm-decision

# Variables d'environnement par défaut (surchargées par Kubernetes ConfigMap)
ENV LLM_BASE_URL=http://localhost:8000
ENV QUARANTINE_PATH=/quarantaine
ENV DECISION_PORT=3005
ENV MANAGER_PORT=3003

EXPOSE 3005

ENTRYPOINT ["/usr/local/bin/llm-decision"]
