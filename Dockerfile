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

# ── Stage 2 : image runtime ───────────────────────────────────────────────────
FROM alpine:3.20

# ca-certificates : HTTPS vers api.osv.dev
# wget            : installation de Syft
RUN apk add --no-cache ca-certificates wget

# Syft (Go statique → compatible musl/Alpine)
# https://github.com/anchore/syft/releases
ARG SYFT_VERSION=1.20.0
RUN ARCH="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" \
    && wget -qO /tmp/syft.tar.gz \
       "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${ARCH}.tar.gz" \
    && tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft \
    && rm /tmp/syft.tar.gz \
    && syft version \
    && apk del wget

WORKDIR /app

COPY --from=builder /app/target/release/cycle-de-vie ./
COPY config/ ./config/

# SBOMs directory — will be populated at runtime; mount a volume to persist
RUN mkdir -p sboms

EXPOSE 3020

ENV PORT=3020 \
    POLL_INTERVAL_SECS=60 \
    WHITELIST_PATH=config/whitelist \
    SBOM_DIR=sboms \
    SYFT_BIN=syft \
    SBOM_REFRESH_INTERVAL_SECS=86400

CMD ["./cycle-de-vie"]
