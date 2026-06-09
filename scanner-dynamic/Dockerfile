# ═══════════════════════════════════════════════════════════════
# Dockerfile — DockDockGo Scanner v1.2
#
# Modes :
#   - API HTTP : ddg-scanner --server (port 3006, défaut)
#   - CLI image       : ddg-scanner <image> [--docker]
#   - CLI quarantaine : ddg-scanner --quarantine <chemin> [--docker]
#
# Le scanner cherche scan_vm.sh dans :
#   1. ./scan_vm.sh (workdir = /app) ← on met ici
#   2. /opt/firecracker/scan_vm.sh
#   3. /home/$USER/scan_vm.sh
#
# Build : docker build -t dockdockgo-scan-dynamique:1.0.0 .
# ═══════════════════════════════════════════════════════════════

# ───────────── STAGE 1 : compilation Rust musl ────────────
FROM rust:1.85-slim AS builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        musl-tools pkg-config && \
    rustup target add x86_64-unknown-linux-musl && \
    rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --target x86_64-unknown-linux-musl

# ───────────── STAGE 2 : image runtime Ubuntu 22.04 ────────────
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Outils système
#   skopeo : reconstruction d'image OCI depuis la quarantaine (sans pull)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl wget gnupg ca-certificates \
        iproute2 iptables \
        openssh-client \
        sudo \
        jq \
        skopeo \
    && rm -rf /var/lib/apt/lists/*

# Docker CLI (pour lancer les containers à observer + docker load)
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable" \
        > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*

# Falco userspace (le driver kernel est fourni par l'hôte)
# Le scanner lit /var/log/falco.log via volume mount
RUN curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
        | gpg --dearmor -o /usr/share/keyrings/falco.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/falco.gpg] https://download.falco.org/packages/deb stable main" \
        > /etc/apt/sources.list.d/falcosecurity.list && \
    apt-get update && \
    FALCO_DRIVER_LOADER=no apt-get install -y --no-install-recommends falco 2>/dev/null || true && \
    rm -rf /var/lib/apt/lists/*

# Firecracker v1.6.0 (hyperviseur microVM)
RUN ARCH=$(uname -m) && \
    wget -q "https://github.com/firecracker-microvm/firecracker/releases/download/v1.6.0/firecracker-v1.6.0-${ARCH}.tgz" -O /tmp/fc.tgz && \
    tar xzf /tmp/fc.tgz -C /tmp && \
    mv "/tmp/release-v1.6.0-${ARCH}/firecracker-v1.6.0-${ARCH}" /usr/local/bin/firecracker && \
    chmod +x /usr/local/bin/firecracker && \
    rm -rf /tmp/fc.tgz "/tmp/release-v1.6.0-${ARCH}"

# Binaire scanner Rust (statique musl, zéro dépendance GLIBC)
COPY --from=builder \
    /build/target/x86_64-unknown-linux-musl/release/docdockgo-scan-dynamique \
    /usr/local/bin/ddg-scanner

# WORKDIR /app : find_script() cherche ./scan_vm.sh en priorité
WORKDIR /app

# Scripts shell
COPY scan_vm.sh ./scan_vm.sh
COPY falco_rules.local.yaml /etc/falco/falco_rules.local.yaml
RUN chmod +x ./scan_vm.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -fsS http://localhost:3006/health || exit 1

EXPOSE 3006

ENTRYPOINT ["/usr/local/bin/ddg-scanner"]
CMD ["--server"]