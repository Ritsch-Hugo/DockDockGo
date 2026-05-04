# ============================================================
# Étape 1 — Build
# On utilise l'image officielle Rust pour compiler le binaire.
# Le workspace entier est copié car llm-manager dépend de llm-common.
# ============================================================
FROM rust:1.85-slim AS builder

WORKDIR /build

# Copier le workspace complet
COPY Cargo.toml Cargo.lock ./
COPY llm-common/ llm-common/
COPY llm-manager/ llm-manager/
COPY llm-decision/ llm-decision/

# Compiler uniquement llm-manager en mode release
RUN cargo build --release -p llm-manager

# ============================================================
# Étape 2 — Image finale
# Image distroless : uniquement glibc + ca-certificates.
# Aucun shell, aucun package système inutile — surface d'attaque minimale.
# ============================================================
FROM gcr.io/distroless/cc-debian12

COPY --from=builder /build/target/release/llm-manager /usr/local/bin/llm-manager

# Variables d'environnement par défaut (surchargées par Kubernetes ConfigMap)
ENV LLM_BASE_URL=http://localhost:8000
ENV MANAGER_PORT=3003

EXPOSE 3003

ENTRYPOINT ["/usr/local/bin/llm-manager"]
