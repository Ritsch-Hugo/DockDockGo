# DockDockGo — Scanner Dynamique de Containers Docker

> Scanner d'analyse **comportementale** d'images Docker, isolé en microVM
> Firecracker, basé sur Falco modern_ebpf et un système de scoring MITRE ATT&CK.
> Capable de reconstruire et scanner une image directement depuis la
> **quarantaine du proxy**, sans jamais faire de `docker pull`.

[![Rust](https://img.shields.io/badge/Rust-1.85+-orange.svg)](https://www.rust-lang.org/)
[![Falco](https://img.shields.io/badge/Falco-modern__ebpf-green.svg)](https://falco.org/)
[![Firecracker](https://img.shields.io/badge/Firecracker-v1.6.0-red.svg)](https://firecracker-microvm.github.io/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blue.svg)](https://attack.mitre.org/)

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Architecture technique](#2-architecture-technique)
3. [Installation des outils hôte](#3-installation-des-outils-hôte)
4. [Installation du scanner](#4-installation-du-scanner)
5. [Utilisation sur l'hôte](#5-utilisation-sur-lhôte)
6. [Utilisation via Docker](#6-utilisation-via-docker)
7. [Modes de scan](#7-modes-de-scan)
8. [API HTTP](#8-api-http)
9. [Intégration proxy (quarantaine)](#9-intégration-proxy-quarantaine)
10. [Format du résultat JSON](#10-format-du-résultat-json)
11. [Règles de détection](#11-règles-de-détection)
12. [Résultats de tests](#12-résultats-de-tests)
13. [Troubleshooting](#13-troubleshooting)
14. [Structure du projet](#14-structure-du-projet)

---

## 1. Vue d'ensemble

À la différence d'un scan statique (CVE, couches d'image), le scanner
dynamique **exécute l'image** dans une sandbox isolée et observe son
comportement réel via eBPF :

- Modifications de fichiers système (`/etc/passwd`, `/etc/shadow`)
- Connexions réseau sortantes (C2, exfiltration, DNS tunneling)
- Fork bombs, tentatives d'évasion de container
- Lecture de credentials (SSH keys, cloud credentials)
- Cryptominers, reverse shells

Le scanner retourne un **score de 0 à 100** avec un verdict, l'explication
du barème et la liste des règles Falco déclenchées.

**Port HTTP** : `3006`

**Particularité sécurité** : le scanner peut reconstruire une image
directement depuis les blobs OCI en quarantaine (récupérés par le proxy),
**sans jamais faire de `docker pull`** ni accéder à Internet.

---

## 2. Architecture technique

```
┌─────────────────────────────────────────────────────────────────────┐
│                           HÔTE LINUX                                 │
│                                                                      │
│  ┌──────────────────────────────────────────┐                       │
│  │  Container ddg-scanner (optionnel)        │                       │
│  │  OU binaire Rust directement sur l'hôte   │                       │
│  │                                            │                       │
│  │  API HTTP :3006  ◀──── MCP / curl / IA    │                       │
│  │  Scanner Rust (axum + bollard + musl)      │                       │
│  │                                            │                       │
│  │  quarantine_path ? → skopeo reconstruit    │                       │
│  │     l'image depuis blobs OCI (sans pull)   │                       │
│  └──────────┬─────────────────────────────────┘                      │
│             │                                                         │
│             │  sudo bash scan_vm.sh <image>                          │
│             ▼                                                         │
│  ┌──────────────────────────────────────────┐                       │
│  │  scan_vm.sh                               │                       │
│  │  → crée interface TAP (ddg-tap0)          │                       │
│  │  → configure NAT iptables                 │                       │
│  │  → lance Firecracker microVM              │                       │
│  └──────────┬─────────────────────────────────┘                      │
│             ▼                                                         │
│  ┌──────────────────────────────────────────┐                       │
│  │  microVM Firecracker (KVM)                │                       │
│  │  Kernel Linux 5.15 custom BTF             │                       │
│  │  ┌────────────────────────────────────┐   │                       │
│  │  │  Ubuntu 22.04 (rootfs ext4 10GB)   │   │                       │
│  │  │  Docker + containerd               │   │                       │
│  │  │  Falco modern_ebpf (CO-RE eBPF)    │   │                       │
│  │  │  Scanner HTTP Rust (port 3006)     │   │                       │
│  │  │  Container observé (image scannée) │   │                       │
│  │  └────────────────────────────────────┘   │                       │
│  └──────────────────────────────────────────┘                       │
│                                                                      │
│  Falco modern_ebpf (service hôte)                                   │
│  → observe syscalls de tous les containers hôte                     │
│  → écrit alertes dans /var/log/falco.log                            │
└─────────────────────────────────────────────────────────────────────┘
```

### Stack technique

| Composant | Technologie | Rôle |
|-----------|-------------|------|
| Scanner | Rust 1.85 musl statique | API HTTP + orchestration |
| Reconstruction | skopeo + docker load | Image depuis blobs OCI (sans pull) |
| Sandbox | Firecracker v1.6.0 (KVM) | Isolation microVM |
| Kernel VM | Linux 5.15 custom (BTF) | Support Falco modern_ebpf |
| Runtime security | Falco modern_ebpf (CO-RE eBPF) | Détection comportementale |
| Container runtime VM | Docker + containerd (cgroup v2) | Exécution image testée |
| Réseau VM | TAP ddg-tap0 + iptables NAT | Connectivité isolée |

---

## 3. Installation des outils hôte

> Ces outils doivent être installés **directement sur la machine hôte**.
> Ils ne peuvent pas être entièrement containerisés car ils nécessitent
> un accès direct au kernel Linux.

### Prérequis matériel

- CPU avec virtualisation matérielle (**VT-x / AMD-V activée dans le BIOS**)
- 8 GB RAM minimum (la VM utilise 2 GB)
- 30 GB disque libre (kernel + rootfs + cache cargo)
- Linux x86_64 (testé sur Ubuntu 24.04)

### 3.1. Falco modern_ebpf

Falco observe les syscalls via eBPF. Son driver doit être chargé dans
le kernel hôte — il ne peut pas être embarqué dans une image Docker
car il doit correspondre exactement au kernel de la machine.

```bash
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
    | sudo gpg --dearmor -o /usr/share/keyrings/falco.gpg

echo "deb [signed-by=/usr/share/keyrings/falco.gpg] \
https://download.falco.org/packages/deb stable main" \
    | sudo tee /etc/apt/sources.list.d/falcosecurity.list

sudo apt-get update && sudo apt-get install -y falco

sudo systemctl enable falco-modern-bpf
sudo systemctl start falco-modern-bpf

sudo sed -i 's/^json_output:.*/json_output: true/' /etc/falco/falco.yaml
sudo sed -i 's/^buffered_outputs:.*/buffered_outputs: false/' /etc/falco/falco.yaml
sudo touch /var/log/falco.log
sudo chmod 644 /var/log/falco.log
sudo chown $USER /var/log/falco.log
sudo systemctl restart falco-modern-bpf

sudo systemctl status falco-modern-bpf
```

### 3.2. Docker

```bash
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) \
signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo usermod -aG docker $USER
newgrp docker
docker run --rm hello-world
```

### 3.3. skopeo (reconstruction image sans pull)

```bash
sudo apt-get install -y skopeo jq
skopeo --version
```

### 3.4. Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup target add x86_64-unknown-linux-musl
sudo apt install -y musl-tools
rustc --version   # doit afficher 1.85+
```

### 3.5. Kernel custom 5.15 BTF (~30 min, une seule fois)

Le kernel Firecracker par défaut ne supporte pas Falco modern_ebpf.
Il faut compiler un kernel custom avec BTF + cgroup_bpf + netfilter NAT.

> **Important** : inclure `NETFILTER_XT_MATCH_ADDRTYPE` pour éviter
> l'erreur `Couldn't load match 'addrtype'` au démarrage de Docker
> dans la VM sur certains kernels.

```bash
# Pahole 1.22 (pas 1.25+ qui génère du BTF incompatible)
cd /tmp
git clone --branch v1.22 https://github.com/acmel/dwarves.git pahole-1.22
cd pahole-1.22 && git submodule update --init --recursive
sudo apt install -y cmake libdw-dev libelf-dev zlib1g-dev
mkdir build && cd build
cmake -D__LIB=lib .. && make -j$(nproc)
sudo cp pahole /usr/bin/pahole
sudo cp libdwarves*.so* /usr/lib/x86_64-linux-gnu/ && sudo ldconfig

# Sources kernel 5.15
cd /tmp
wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.15.tar.xz
tar xf linux-5.15.tar.xz && cd linux-5.15

sed -i '1i #pragma GCC diagnostic ignored "-Wuse-after-free"' \
    tools/lib/subcmd/subcmd-util.h

make defconfig && make kvm_guest.config

for opt in VIRTIO_MMIO VIRTIO_MMIO_CMDLINE_DEVICES VIRTIO_BLK \
           DEBUG_INFO DEBUG_INFO_BTF DEBUG_INFO_DWARF4 \
           BPF BPF_SYSCALL BPF_EVENTS BPF_JIT \
           FTRACE FTRACE_SYSCALLS PERF_EVENTS \
           KPROBES UPROBES TRACEPOINTS \
           CGROUPS CGROUP_BPF CGROUP_DEVICE MEMCG \
           NF_NAT IP_NF_NAT NETFILTER_XT_NAT \
           NETFILTER_XT_MATCH_ADDRTYPE \
           BRIDGE_NETFILTER VETH OVERLAY_FS; do
    scripts/config --enable CONFIG_$opt
done
yes "" | make olddefconfig

yes "" | make -j$(nproc) \
    KCFLAGS="-Wno-error=use-after-free" \
    HOSTCFLAGS="-Wno-error=use-after-free" \
    vmlinux

sudo mkdir -p /opt/firecracker
sudo strip --strip-debug --keep-section=.BTF \
    -o /opt/firecracker/vmlinux vmlinux
```

---

## 4. Installation du scanner

```bash
git clone https://github.com/Ritsch-Hugo/DocDockGo.git
cd DocDockGo/docdockgo-scan-dynamique

# Setup complet de la microVM (~15 min)
sudo env PATH=$PATH bash setup_firecracker.sh

# Automatisation MCP (sudo sans mot de passe pour scan_vm.sh)
sudo bash setup_mcp_automation.sh

ls /opt/firecracker/
# vmlinux  ddg-rootfs.ext4  ddg-vm-key  ddg-vm-key.pub
```

### 4.1. Mise à jour du binaire dans le rootfs

Si tu recompiles le scanner, mets à jour le binaire **dans le rootfs** VM.
Le scanner avertit automatiquement au démarrage si le rootfs est obsolète.

```bash
cargo build --release --target x86_64-unknown-linux-musl

sudo mkdir -p /tmp/ddg-mount
sudo mount -o loop /opt/firecracker/ddg-rootfs.ext4 /tmp/ddg-mount
sudo cp target/x86_64-unknown-linux-musl/release/docdockgo-scan-dynamique \
    /tmp/ddg-mount/usr/local/bin/ddg-scanner
sudo umount /tmp/ddg-mount && sudo rmdir /tmp/ddg-mount
```

---

## 5. Utilisation sur l'hôte

### 5.1. Mode CLI — par nom d'image

```bash
# Scan via microVM Firecracker (recommandé)
sudo bash scan_vm.sh nginx:alpine

# Scan via Docker direct (plus rapide)
cargo run --release -- nginx:alpine --docker
cargo run --release -- nginx:alpine            # mode VM par défaut
```

### 5.2. Mode CLI — depuis la quarantaine (sans pull)

```bash
# Reconstruit l'image depuis les blobs OCI puis scanne
cargo run --release -- --quarantine /chemin/quarantaine/library/alpine/3.18
cargo run --release -- --quarantine /chemin/quarantaine/library/alpine/3.18 --docker
```

### 5.3. Mode API HTTP

```bash
cargo run --release -- --server &

curl http://localhost:3006/health        # → DockDockGo OK

# Par nom d'image
curl -X POST http://localhost:3006/scan \
  -H "Content-Type: application/json" \
  -d '{"image": "nginx:alpine", "mode": "vm"}' | jq

# Depuis la quarantaine (sans pull)
curl -X POST http://localhost:3006/scan \
  -H "Content-Type: application/json" \
  -d '{"quarantine_path": "/chemin/quarantaine/library/alpine/3.18", "mode": "vm"}' | jq
```

---

## 6. Utilisation via Docker

> Le container embarque le scanner Rust + Firecracker + skopeo.
> Il utilise Falco de l'hôte via volume mount (pattern Falco Sidekick).
> **Prérequis** : les outils hôte (sections 3 et 4) doivent être installés.

### 6.1. Build de l'image

```bash
cd DocDockGo/docdockgo-scan-dynamique
docker build -t dockdockgo-scan-dynamique:1.0.0 .
```

### 6.2. Lancement avec docker run

```bash
docker run -d \
  --name ddg-scanner \
  --privileged \
  --network host \
  --device /dev/kvm:/dev/kvm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /opt/firecracker:/opt/firecracker \
  -v /var/log/falco.log:/var/log/falco.log \
  -v /chemin/proxy/quarantaine:/quarantaine:ro \
  --restart unless-stopped \
  dockdockgo-scan-dynamique:1.0.0
```

### 6.3. Lancement avec docker-compose

```bash
# Indique le chemin de la quarantaine du proxy
QUARANTINE_PATH=/chemin/proxy/quarantaine docker-compose up -d

docker-compose down     # arrêt
```

### 6.4. Explication des accès hôte requis

| Accès | Type | Justification |
|-------|------|---------------|
| `--privileged` | Capacités | KVM (Firecracker) + eBPF + iptables NAT |
| `--network host` | Réseau | Interface TAP `ddg-tap0` sur l'hôte |
| `/dev/kvm` | Device | Firecracker lance des microVMs via KVM |
| `/var/run/docker.sock` | Volume | Lance les containers + `docker load` |
| `/opt/firecracker` | Volume **RW** | Kernel + rootfs (Firecracker ouvre en O_RDWR) |
| `/var/log/falco.log` | Volume | Alertes Falco du driver hôte |
| `quarantaine` | Volume **RO** | Blobs OCI du proxy (mode quarantine_path) |

> **Pourquoi Falco reste sur l'hôte ?**
> Le driver eBPF Falco doit correspondre exactement au kernel hôte.
> Il ne peut pas être compilé au build d'une image Docker. C'est le
> pattern **Falco Sidekick** : Falco tourne sur l'hôte, le scanner lit
> `/var/log/falco.log` via volume. Même architecture que Sysdig et Aqua.

### 6.5. Commandes utiles

```bash
docker logs -f ddg-scanner        # logs en direct
docker stop ddg-scanner           # arrêt
docker exec ddg-scanner /usr/local/bin/ddg-scanner nginx:alpine --docker
```

---

## 7. Modes de scan

Le scanner combine deux **moteurs d'isolation** et deux **sources d'image**.

### Moteurs d'isolation

| Mode | Isolation | Durée | Cas d'usage |
|------|-----------|-------|-------------|
| `docker` | Container hôte | ~10s | Images de confiance, scan rapide |
| `vm` | microVM Firecracker (KVM) | ~30-45s | Images inconnues, isolation maximale |

### Sources d'image

| Source | Champ | Comportement |
|--------|-------|--------------|
| Nom d'image | `image` | Pull si absente, puis scan |
| Quarantaine | `quarantine_path` | Reconstruit depuis blobs OCI, **sans pull** |

> **Sécurité** : le mode `quarantine_path` n'accède jamais à Internet.
> L'image est reconstruite localement avec skopeo depuis les blobs déjà
> récupérés par le proxy, puis chargée dans la sandbox via `docker load`.

---

## 8. API HTTP

| Méthode | URL | Description |
|---------|-----|-------------|
| `GET` | `/health` | Healthcheck → `DockDockGo OK` |
| `POST` | `/scan` | Lance un scan |

### Body POST `/scan`

```json
{
  "image": "nginx:alpine",
  "mode": "vm"
}
```
ou
```json
{
  "quarantine_path": "/quarantaine/library/alpine/3.18",
  "mode": "vm"
}
```

| Champ | Présence | Description |
|-------|----------|-------------|
| `image` | si pas de quarantine_path | Nom Docker complet |
| `quarantine_path` | si pas d'image | Chemin absolu du dossier de quarantaine |
| `mode` | optionnel (défaut "vm") | `"vm"` ou `"docker"` |

---

## 9. Intégration proxy (quarantaine)

Dans le pipeline DocDockGo, le scanner est appelé par le **mcp-tools-server**
via l'outil `run_dynamic_scan`, qui transmet le `quarantine_path`.

### Flux d'intégration

```
Client docker pull
      │
      ▼
  PROXY MITM ──► met les blobs OCI en quarantaine/
      │
      ▼
  Orchestrateur ──► LLM-Decision ──► mcp-tools-server
                                          │
                                          │ run_dynamic_scan
                                          │ {quarantine_path}
                                          ▼
                              Scanner dynamique :3006
                                          │
                                          ├─ skopeo : blobs → image (sans pull)
                                          ├─ docker load dans la sandbox
                                          ├─ scan Falco (docker ou VM)
                                          └─ nettoyage (tmp + image)
                                          │
                                          ▼
                              JSON score + verdict + détails
```

### Structure de quarantaine attendue

```
<quarantine_path>/          ex: /quarantaine/library/alpine/3.18
├── manifests/              → manifests OCI (index, image, attestations)
│   └── <digest>.json
├── blobs/sha256/           → config + layers (nommés par digest)
│   └── <digest>
└── referrers/              → SBOM, signatures (ignoré)
```

Le scanner sélectionne automatiquement le **manifest image de la bonne
architecture** (mediaType image.manifest + config architecture=amd64),
ignore les index multi-arch et les attestations, reconstruit un OCI layout
temporaire, puis utilise skopeo pour produire un tar chargeable.

---

## 10. Format du résultat JSON

```json
{
  "image": "/quarantaine/library/alpine/3.18",
  "score": 15,
  "critical": false,
  "verdict": "LOW",
  "allowed": true,
  "mode": "vm",
  "scoring_explanation": "Score 0-100 basé sur la sévérité des règles Falco...",
  "rule_counts": {
    "DDG Shell Spawn": 1
  },
  "details": [
    "Notice [DDG] Shell spawned (command=sh container=...) ..."
  ]
}
```

| Champ | Description |
|-------|-------------|
| `score` | 0-100 (sévérité agrégée, cappé) |
| `critical` | true si règle CRITICAL déclenchée |
| `verdict` | CLEAN / LOW / MODERATE / HIGH / CRITICAL |
| `allowed` | true si score < 60 ET pas de critical |
| `mode` | moteur d'isolation utilisé |
| `scoring_explanation` | barème expliqué (toujours présent) |
| `rule_counts` | nombre d'alertes par règle |
| `details` | logs Falco détaillés (toujours inclus) |

### Verdicts

| Score | Verdict | Allowed |
|-------|---------|---------|
| 0 | CLEAN | ✅ true |
| 1-29 | LOW | ✅ true |
| 30-59 | MODERATE | ✅ true |
| 60-89 | HIGH | ❌ false |
| 90-100 | CRITICAL | ❌ false |

> `allowed=false` si une règle CRITICAL est déclenchée, quel que soit le score.

---

## 11. Règles de détection

18 règles Falco DDG organisées en 9 catégories MITRE ATT&CK :

| Catégorie | Règles | MITRE |
|-----------|--------|-------|
| Accès fichiers sensibles | Sensitive File, SSH Key, Cloud Creds | T1552 |
| Exécution | Shell Spawn, Suspicious Interpreter | T1059 |
| Réseau | Outbound, Network Tool, Reverse Shell | T1071, T1095 |
| Évasion | Mount, Setuid, Container Escape | T1611, T1068 |
| Persistance | System File Mod, Cron | T1136, T1543 |
| Anti-forensic | Log Tampering | T1070 |
| DoS | Fork Bomb | T1499 |
| Cryptomining | Cryptominer Pattern | T1496 |
| Découverte | Discovery Commands | T1083 |

Alignement standards : **NIST SP 800-190**, **CIS Docker Benchmark**,
**OWASP Container Security**.

---

## 12. Résultats de tests

### Fiabilité mode VM Firecracker

| Image | Score | Verdict | Autorisé |
|-------|-------|---------|----------|
| `alpine:3.18` (quarantaine) | 15/100 | LOW | ✅ true |
| `nginx:alpine` | 0/100 | CLEAN | ✅ true |
| `python:3.11-slim` | 0/100 | CLEAN | ✅ true |
| `httpd:alpine` | 40/100 | MODERATE | ✅ true |
| `dockdockgo-evil` | 100/100 | CRITICAL | ❌ false |

### Reconstruction depuis quarantaine validée

```bash
# Mode docker : reconstruit alpine depuis blobs OCI, sans pull
cargo run --release -- --quarantine /tmp/quarantaine/library/alpine/3.18 --docker
# → SCORE : 15/100, verdict LOW, allowed true

# Mode VM : idem en microVM Firecracker isolée
cargo run --release -- --quarantine /tmp/quarantaine/library/alpine/3.18
# → SCORE : 15/100, verdict LOW, allowed true
```

Aucun `docker pull`, aucun accès Internet : l'image est reconstruite
uniquement depuis les blobs en quarantaine. La quarantaine d'origine
n'est jamais modifiée (lecture seule).

---

## 13. Troubleshooting

### Erreur : `Couldn't load match 'addrtype'`

Module kernel `xt_addrtype` absent. Le scanner configure Docker dans la
VM avec `"iptables": false` pour contourner. Si persiste, recompiler le
kernel avec `CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=y` (section 3.5).

### Erreur : `structure needs cleaning` (rootfs corrompu)

Le rootfs VM ext4 est corrompu (souvent après un montage pendant qu'un
scan tournait). Réparer avec :

```bash
sudo umount /tmp/ddg-mount 2>/dev/null
sudo e2fsck -f -y /opt/firecracker/ddg-rootfs.ext4
```

Puis remettre le binaire à jour dans le rootfs (section 4.1).

> **Prévention** : ne jamais monter le rootfs (`mount -o loop`) pendant
> qu'un scan VM est en cours.

### Erreur : `Binaire rootfs VM OBSOLÈTE`

Le binaire dans le rootfs diffère du binaire courant. Le scanner affiche
la commande exacte de mise à jour au démarrage (section 4.1).

### Erreur : `cannot write to a ... directory/symlink`

Résidu de transfert dans le rootfs. `scan_vm.sh` nettoie désormais
automatiquement `/tmp/ddg-image.tar` dans la VM avant chaque transfert.

### Erreur : reconstruction quarantaine échoue

Vérifier que skopeo est installé (`skopeo --version`) et que la structure
de quarantaine contient bien `manifests/` et `blobs/sha256/`.

### Erreur : `/dev/kvm absent`

Activer VT-x/AMD-V dans le BIOS. Sur VM hôte, activer la nested virtualization.

---

## 14. Structure du projet

```
docdockgo-scan-dynamique/
├── src/
│   ├── main.rs                    # Scanner Rust + API HTTP + scoring
│   ├── quarantine.rs              # Reconstruction image depuis quarantaine
│   └── sandbox/
│       ├── docker.rs              # Gestion containers via bollard
│       ├── seccomp.rs             # Profils seccomp (préparation future)
│       └── mod.rs
├── seccomp/
│   ├── seccomp-ddg.json
│   └── seccomp-ddg-strict.json
├── falco_rules.local.yaml         # 18 règles Falco DDG (MITRE ATT&CK)
├── Cargo.toml / Cargo.lock
├── Dockerfile                     # Image dockdockgo-scan-dynamique:1.0.0
├── docker-compose.yml             # Déploiement avec accès hôte documentés
├── install.sh                     # Setup Falco hôte
├── setup_firecracker.sh           # Setup microVM complète
├── scan_vm.sh                     # Lance un scan dans Firecracker
├── setup_mcp_automation.sh        # Sudoers NOPASSWD pour MCP/IA
├── test_reliability.sh            # Tests fiabilité multi-images
└── .gitignore
```

---
