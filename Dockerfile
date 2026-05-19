# ── Stage 1 : compilation ────────────────────────────────────────────────────
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app

# Cache des dépendances — recompilées seulement si Cargo.toml/Cargo.lock changent
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src

# Compilation du code source réel
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ── Stage 2 : image runtime minimale ─────────────────────────────────────────
FROM alpine:3.20

# ca-certificates requis pour les appels HTTPS vers api.osv.dev
RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/target/release/cycle-de-vie ./
COPY config/ ./config/

EXPOSE 3020

# Valeurs par défaut — toutes surchargeable via variables d'environnement
ENV PORT=3020 \
    POLL_INTERVAL_SECS=60 \
    WHITELIST_PATH=config/whitelist

CMD ["./cycle-de-vie"]
