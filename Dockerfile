# ============================================================
# ÉTAPE 1 : BUILD (Compilation)
# ============================================================
FROM rust:slim-bookworm as builder

# Installation des dépendances système pour compiler (notamment pour reqwest/rustls et openssl si besoin)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copie des fichiers de dépendances en premier pour optimiser le cache Docker
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY template ./template
COPY .sqlx .sqlx
# Compilation en mode Release
# Le binaire s'appellera 'DockDockGo' car c'est le 'name' dans Cargo.toml
RUN cargo build --release --all-features

# ============================================================
# ÉTAPE 2 : RUNTIME (Image finale minimale)
# ============================================================
FROM debian:bookworm-slim

# Installation des librairies runtime nécessaires (SSL pour reqwest)
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1000 -s /bin/bash appuser

WORKDIR /app

# Copie du binaire compilé (Nom corrigé : DockDockGo)
COPY --from=builder /app/target/release/DockDockGo /app/DockDockGo

# Copie du dossier template (au cas où, bien que include_str! les intègre souvent au binaire)
COPY --from=builder /app/template /app/template

# Sécurisation des droits
RUN chown -R appuser:appuser /app

# Passage à l'utilisateur non-root
USER appuser

# Exposition du port défini dans main.rs
EXPOSE 3000

# Commande de lancement
CMD ["./DockDockGo"]
