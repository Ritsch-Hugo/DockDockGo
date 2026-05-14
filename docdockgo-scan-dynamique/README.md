# DockDockGo — Scanner Dynamique de Containers Docker

> Scanner d'analyse **comportementale** d'images Docker, isolé en microVM
> Firecracker, basé sur Falco modern_ebpf et un système de scoring MITRE ATT&CK.

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
7. [API HTTP](#7-api-http)
8. [Intégration MCP / IA](#8-intégration-mcp--ia)
9. [Format du résultat JSON](#9-format-du-résultat-json)
10. [Règles de détection](#10-règles-de-détection)
11. [Résultats de tests](#11-résultats-de-tests)
12. [Structure du projet](#12-structure-du-projet)

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

Le scanner retourne un **score de 0 à 100** avec un verdict et la liste
des règles Falco déclenchées.

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
│  │  API HTTP :8080  ◀──── MCP / curl / IA   │                       │
│  │  Scanner Rust (axum + bollard + musl)      │                       │
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
│  │  │  Scanner HTTP Rust (port 8080)     │   │                       │
│  │  │                                    │   │                       │
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
# Ajout du repo Falco
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
    | sudo gpg --dearmor -o /usr/share/keyrings/falco.gpg

echo "deb [signed-by=/usr/share/keyrings/falco.gpg] \
https://download.falco.org/packages/deb stable main" \
    | sudo tee /etc/apt/sources.list.d/falcosecurity.list

sudo apt-get update && sudo apt-get install -y falco

# Active le service modern_ebpf
sudo systemctl enable falco-modern-bpf
sudo systemctl start falco-modern-bpf

# Configuration JSON + fichier log
sudo sed -i 's/^json_output:.*/json_output: true/' /etc/falco/falco.yaml
sudo sed -i 's/^buffered_outputs:.*/buffered_outputs: false/' /etc/falco/falco.yaml
sudo touch /var/log/falco.log
sudo chmod 644 /var/log/falco.log
sudo chown $USER /var/log/falco.log
sudo systemctl restart falco-modern-bpf

# Copie les règles DDG
sudo cp falco_rules.local.yaml /etc/falco/falco_rules.local.yaml
sudo systemctl restart falco-modern-bpf

# Vérification
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
```

### 3.3. Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup target add x86_64-unknown-linux-musl
sudo apt install -y musl-tools
```

### 3.4. Kernel custom 5.15 BTF (~30 min, une seule fois)

Le kernel Firecracker par défaut ne supporte pas Falco modern_ebpf.
Il faut compiler un kernel custom avec BTF + cgroup_bpf + netfilter NAT.

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

# Patch GCC 13+ (faux positif use-after-free)
sed -i '1i #pragma GCC diagnostic ignored "-Wuse-after-free"' \
    tools/lib/subcmd/subcmd-util.h

# Configuration
make defconfig && make kvm_guest.config

for opt in VIRTIO_MMIO VIRTIO_MMIO_CMDLINE_DEVICES VIRTIO_BLK \
           DEBUG_INFO DEBUG_INFO_BTF DEBUG_INFO_DWARF4 \
           BPF BPF_SYSCALL BPF_EVENTS BPF_JIT \
           FTRACE FTRACE_SYSCALLS PERF_EVENTS \
           KPROBES UPROBES TRACEPOINTS \
           CGROUPS CGROUP_BPF CGROUP_DEVICE MEMCG \
           NF_NAT IP_NF_NAT NETFILTER_XT_NAT \
           BRIDGE_NETFILTER VETH OVERLAY_FS; do
    scripts/config --enable CONFIG_$opt
done
yes "" | make olddefconfig

# Compilation (~20 min)
yes "" | make -j$(nproc) \
    KCFLAGS="-Wno-error=use-after-free" \
    HOSTCFLAGS="-Wno-error=use-after-free" \
    vmlinux

# Installation
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

# Automatisation MCP (sudo sans mot de passe)
sudo bash setup_mcp_automation.sh

# Vérification
ls /opt/firecracker/
# vmlinux  ddg-rootfs.ext4  ddg-vm-key  ddg-vm-key.pub
```

---

## 5. Utilisation sur l'hôte

### Mode CLI

```bash
# Scan via microVM Firecracker (recommandé)
sudo bash scan_vm.sh nginx:alpine
sudo bash scan_vm.sh dockdockgo-evil --details

# Scan via Docker direct (plus rapide)
cargo run --release -- nginx:alpine --docker
```

### Mode API HTTP sur l'hôte

```bash
# Lance l'API
cargo run --release -- --server &

# Healthcheck
curl http://localhost:8080/health

# Scan mode VM
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"image": "nginx:alpine", "mode": "vm"}'

# Scan mode Docker
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"image": "nginx:alpine", "mode": "docker"}'
```

---

## 6. Utilisation via Docker

### Build de l'image

```bash
cd DocDockGo/docdockgo-scan-dynamique

docker build -t dockdockgo-scan-dynamique:1.0.0 .
```

### Lancement avec docker run

```bash
docker run -d \
  --name ddg-scanner \
  --privileged \
  --network host \
  --device /dev/kvm:/dev/kvm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /opt/firecracker:/opt/firecracker \
  -v /var/log/falco.log:/var/log/falco.log \
  --restart unless-stopped \
  dockdockgo-scan-dynamique:1.0.0
```

### Lancement avec docker-compose

```bash
docker-compose up -d    # démarrage
docker-compose down     # arrêt
```

### Explication des accès hôte requis

Le `docker-compose.yml` déclare explicitement tous les accès nécessaires :

| Accès | Type | Justification |
|-------|------|---------------|
| `--privileged` | Capacités système | KVM (Firecracker) + eBPF (Falco) + iptables NAT |
| `--network host` | Réseau | Accès à l'interface TAP `ddg-tap0` (réseau microVM) |
| `/dev/kvm` | Device | Firecracker lance des microVMs via KVM matériel |
| `/var/run/docker.sock` | Volume | Lance et observe les containers à scanner |
| `/opt/firecracker` | Volume RW | Kernel 5.15 BTF + rootfs Ubuntu (O_RDWR requis) |
| `/var/log/falco.log` | Volume | Lecture des alertes Falco du driver hôte |

> **Pourquoi Falco reste sur l'hôte ?**
> Le driver eBPF de Falco doit correspondre exactement au kernel hôte.
> Il ne peut pas être compilé au build d'une image Docker (kernel cible
> inconnu). C'est le pattern **Falco Sidekick** utilisé en production :
> Falco tourne sur l'hôte, le scanner containerisé lit `/var/log/falco.log`
> via volume mount. Même architecture que Sysdig Secure et Aqua Enforcer.

### Commandes utiles

```bash
docker logs ddg-scanner           # logs
docker logs -f ddg-scanner        # logs en direct
docker stop ddg-scanner           # arrêt
docker rm ddg-scanner             # suppression
docker images | grep dockdockgo   # taille image
```

### Tests depuis le container

```bash
# Healthcheck
curl http://localhost:8080/health

# Scan mode Docker (via le container)
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"image": "nginx:alpine", "mode": "docker"}'

# Scan mode VM (depuis le container, ~30-45s)
curl --max-time 120 -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"image": "dockdockgo-evil", "mode": "vm"}'
```

---

## 7. API HTTP

| Méthode | URL | Description |
|---------|-----|-------------|
| `GET` | `/health` | Healthcheck → `DockDockGo OK` |
| `POST` | `/scan` | Lance un scan |

**Body de la requête POST `/scan` :**
```json
{
  "image": "nginx:alpine",
  "mode": "vm"
}
```

---

## 8. Intégration MCP / IA

### Tool MCP Python

```python
from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP("dockdockgo-scanner")

@mcp.tool()
def scan_docker_image(image: str, mode: str = "vm") -> dict:
    """
    Analyse comportementale d'une image Docker via Falco modern_ebpf
    dans une microVM Firecracker isolée.

    Args:
        image : ex: "nginx:alpine", "python:3.11"
        mode  : "vm" (recommandé) ou "docker"

    Returns:
        dict avec score, verdict, allowed, critical, rule_counts, details
    """
    response = requests.post(
        "http://localhost:8080/scan",
        json={"image": image, "mode": mode},
        timeout=120,
    )
    return response.json()

if __name__ == "__main__":
    mcp.run()
```

### Décision par l'IA

```python
result = scan_docker_image("nginx:alpine", mode="docker")

if result["allowed"]:
    print(f"✓ {result['image']} autorisée (score {result['score']})")
else:
    print(f"✗ {result['image']} BLOQUÉE — {result['verdict']}")
    for rule, count in result["rule_counts"].items():
        print(f"    - {rule} × {count}")
```

---

## 9. Format du résultat JSON

```json
{
  "image": "dockdockgo-evil",
  "score": 100,
  "critical": true,
  "verdict": "CRITICAL",
  "allowed": false,
  "mode": "docker",
  "rule_counts": {
    "DDG System File Modification": 1,
    "DDG Shell Spawn": 2,
    "DDG Outbound Connection": 2,
    "DDG Suspicious Network Tool": 1,
    "DDG Mount Attempt": 1,
    "Read sensitive file untrusted": 1
  },
  "details": [
    "Critical [DDG] System file modification (file=/etc/passwd ...)",
    "Notice [DDG] Shell spawned (command=sh -c ...)",
    "Warning [DDG] Outbound connection attempt (command=nslookup ...)"
  ]
}
```

### Verdicts

| Score | Verdict | Allowed | Action |
|-------|---------|---------|--------|
| 0 | `CLEAN` | ✅ true | Image autorisée |
| 1-29 | `LOW` | ✅ true | Autorisée, log warning |
| 30-59 | `MODERATE` | ✅ true | Analyse manuelle conseillée |
| 60-89 | `HIGH` | ❌ false | Image bloquée |
| 90-100 | `CRITICAL` | ❌ false | Bloquée + alerte |

---

## 10. Règles de détection

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

## 11. Résultats de tests

### Fiabilité mode VM Firecracker

| Image | Score | Verdict | Autorisé |
|-------|-------|---------|----------|
| `alpine:latest` | 15/100 | LOW | ✅ true |
| `busybox:latest` | 15/100 | LOW | ✅ true |
| `python:3.11-slim` | 0/100 | CLEAN | ✅ true |
| `node:20-alpine` | 0/100 | CLEAN | ✅ true |
| `nginx:alpine` | 0/100 | CLEAN | ✅ true |
| `redis:alpine` | 0/100 | CLEAN | ✅ true |
| `httpd:alpine` | 40/100 | MODERATE | ✅ true |
| **`dockdockgo-evil`** | **100/100** | **CRITICAL** | **❌ false** |

### Métriques

| Métrique | Valeur |
|----------|--------|
| Vrais positifs (TP) | 1/1 |
| Vrais négatifs (TN) | 6/7 |
| Faux positifs (FP) | 1 (httpd — DNS Apache) |
| **Accuracy** | **~86%** |

### Preuve d'isolation VM

```bash
# Hash avant scan
md5sum /etc/passwd   # a1b2c3d4... /etc/passwd

sudo bash scan_vm.sh dockdockgo-evil   # modifie /etc/passwd DANS la VM

# Hash après scan
md5sum /etc/passwd   # a1b2c3d4... /etc/passwd  ← identique
```

L'hôte n'est pas touché. L'isolation Firecracker est prouvée.

### Containerisation validée

```bash
# CLEAN depuis le container
curl -X POST http://localhost:8080/scan \
  -d '{"image":"nginx:alpine","mode":"docker"}'
# → score: 0, verdict: CLEAN, allowed: true

# CRITICAL depuis le container (mode VM)
curl -X POST http://localhost:8080/scan \
  -d '{"image":"dockdockgo-evil","mode":"vm"}'
# → score: 100, verdict: CRITICAL, allowed: false
```

---

## 12. Structure du projet

```
docdockgo-scan-dynamique/
├── src/
│   ├── main.rs                    # Scanner Rust + API HTTP
│   └── sandbox/
│       ├── docker.rs              # Gestion containers (bollard)
│       ├── seccomp.rs             # Profils seccomp
│       └── mod.rs
├── seccomp/
│   ├── seccomp-ddg.json
│   └── seccomp-ddg-strict.json
├── falco_rules.local.yaml         # 18 règles Falco DDG
├── Cargo.toml / Cargo.lock
├── Dockerfile                     # Image dockdockgo-scan-dynamique:1.0.0
├── docker-compose.yml             # Accès hôte documentés
├── install.sh                     # Setup Falco hôte
├── setup_firecracker.sh           # Setup microVM
├── scan_vm.sh                     # Lance un scan VM
├── setup_mcp_automation.sh        # Sudoers NOPASSWD pour MCP
├── test_reliability.sh            # Tests fiabilité multi-images
└── .gitignore
```

---

## Équipe

Projet ISEN Méditerranée — Cybersécurité ISEN4 2025-2026

- **Mendy** — Scanner dynamique Rust + Firecracker + Falco
- **Lenny, Hugo, Camille** — Orchestrateur, MCP, scanner statique
- **Antoine** — Project Manager
- **Tuteur** : Mr. Paillart
