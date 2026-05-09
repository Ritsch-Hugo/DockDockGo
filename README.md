# DockDockGo — Scanner dynamique 

Scanner d'analyse comportementale d'images Docker, isolé en **microVM Firecracker**, basé sur **Falco modern_ebpf** et un système de scoring personnalisé.

À la différence d'un scan statique (CVE), le scan dynamique exécute l'image dans une sandbox isolée et observe son comportement en temps réel via eBPF : modifications de fichiers système, connexions sortantes, fork bombs, tentatives d'évasion, cryptominers, etc.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                       HÔTE LINUX                         │
│                                                          │
│  ┌──────────────┐         ┌─────────────────────┐       │
│  │ MCP / IA     │ POST    │   Scanner Rust      │       │
│  │ (Qwen 2.5)   │────────▶│   (HTTP :8080)      │       │
│  └──────────────┘  /scan  └──────────┬──────────┘       │
│                                       │                  │
│                                       ▼                  │
│                            ┌──────────────────────┐     │
│                            │  scan_vm.sh          │     │
│                            │  (sudo NOPASSWD)     │     │
│                            └──────────┬───────────┘     │
│                                       │                  │
│                                       ▼                  │
│                       ┌────────────────────────────┐    │
│                       │   microVM Firecracker      │    │
│                       │  ┌──────────────────────┐  │    │
│                       │  │ Ubuntu 22.04         │  │    │
│                       │  │ + Docker             │  │    │
│                       │  │ + Falco modern_ebpf  │  │    │
│                       │  │ + Scanner HTTP       │  │    │
│                       │  │                      │  │    │
│                       │  │ Container observé    │  │    │
│                       │  │ (image scannée)      │  │    │
│                       │  └──────────────────────┘  │    │
│                       └────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

**Stack technique :**

- **Sandbox** : microVM Firecracker (KVM, ~125 ms boot)
- **Kernel VM** : Linux 5.15 custom (BTF + virtio_mmio + cgroup_bpf)
- **Runtime security** : Falco modern_ebpf (CO-RE eBPF, kernel ≥ 5.11)
- **Container runtime** : Docker (cgroup v2)
- **Scanner** : Rust statique musl (axum + bollard)
- **18 règles** Falco DDG couvrant 9 catégories MITRE ATT&CK

---

## Prérequis

### Matériel

- CPU avec virtualisation matérielle (VT-x / AMD-V activée dans le BIOS)
- 8 GB RAM minimum (la VM utilise 2 GB)
- 30 GB disque libre (kernel + rootfs + cache cargo)

### Logiciel

- Linux x86_64 (testé sur Ubuntu 24.04)
- Docker installé sur l'hôte
- Rust ≥ 1.75 (avec `cargo`)

---

## Installation

L'installation se fait en **3 étapes** : compiler le kernel custom, construire la microVM, puis activer l'automatisation MCP.

### Étape 1 — Kernel custom (~30 min, une seule fois)

Le kernel Firecracker par défaut n'a pas BTF + cgroup_bpf + netfilter NAT, donc on doit en compiler un sur mesure.

> **Note importante** : il faut utiliser **pahole 1.22** (pas 1.25+) car le format BTF généré doit être compatible avec le kernel 5.15.

```bash
# 1. Pahole 1.22
cd /tmp
git clone --branch v1.22 https://github.com/acmel/dwarves.git pahole-1.22
cd pahole-1.22 && git submodule update --init --recursive
sudo apt install -y cmake libdw-dev libelf-dev zlib1g-dev
mkdir build && cd build
cmake -D__LIB=lib .. && make -j$(nproc)
sudo cp pahole /usr/bin/pahole
sudo cp libdwarves*.so* /usr/lib/x86_64-linux-gnu/ && sudo ldconfig

# 2. Sources kernel 5.15
cd /tmp
wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.15.tar.xz
tar xf linux-5.15.tar.xz && cd linux-5.15

# 3. Patch GCC 13+ (faux positif use-after-free)
sed -i '1i #pragma GCC diagnostic ignored "-Wuse-after-free"' \
    tools/lib/subcmd/subcmd-util.h

# 4. Configuration
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

# 5. Compilation (~20 min)
yes "" | make -j$(nproc) \
    KCFLAGS="-Wno-error=use-after-free" \
    HOSTCFLAGS="-Wno-error=use-after-free" \
    KBUILD_HOSTCFLAGS="-Wno-error=use-after-free" \
    vmlinux

# 6. Installation
sudo mkdir -p /opt/firecracker
sudo strip --strip-debug --keep-section=.BTF \
    -o /opt/firecracker/vmlinux vmlinux
```

### Étape 2 — Setup Firecracker + Rootfs (~15 min)

```bash
git clone https://github.com/Ritsch-Hugo/DocDockGo.git
cd DocDockGo/docdockgo-scan-dynamique

sudo env PATH=$PATH bash setup_firecracker.sh
```

Le script installe :
- Firecracker v1.6.0 (binaire `/usr/local/bin/firecracker`)
- Rootfs Ubuntu 22.04 ext4 10GB (`/opt/firecracker/ddg-rootfs.ext4`)
- Docker dans la VM avec config bridge fonctionnelle
- Falco modern_ebpf avec les 18 règles DDG
- Scanner Rust statique musl
- Réseau TAP persistant (`172.16.0.1` ↔ `172.16.0.2`)

### Étape 3 — Automatisation MCP (1 min)

Pour permettre à l'IA d'appeler le scanner sans interaction (sudo sans mot de passe) :

```bash
sudo bash setup_mcp_automation.sh
```

Vérification :

```bash
# Doit marcher SANS demander de mot de passe
sudo -n bash scan_vm.sh dockdockgo-evil
```

---

## Lancer un scan

### Mode 1 — CLI direct (humain)

```bash
# Scan via microVM (recommandé)
sudo bash scan_vm.sh nginx:alpine

# Avec détails Falco
sudo bash scan_vm.sh dockdockgo-evil --details

# Mode Docker direct (sans VM, plus rapide mais moins isolé)
cargo run --release -- nginx:alpine --docker
```

### Mode 2 — HTTP API (programmatique)

```bash
# Lance le scanner en mode serveur
cargo run --release -- --server
# → http://localhost:8080
```

**Endpoints** :

| Méthode | URL | Body | Description |
|---------|-----|------|-------------|
| `POST` | `/scan` | `{"image": "...", "mode": "vm"\|"docker"}` | Lance un scan |
| `GET` | `/health` | — | Healthcheck |

**Exemple curl** :

```bash
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"image": "nginx:alpine", "mode": "vm"}'
```

---

## Lancer un scan via MCP / IA

L'orchestrateur (Qwen 2.5 + arbiter via MCP) peut appeler le scanner par subprocess ou HTTP.

### Méthode 1 — Tool MCP en Python

```python
from mcp.server.fastmcp import FastMCP
import subprocess
import json

mcp = FastMCP("dockdockgo-scanner")

@mcp.tool()
def scan_docker_image(image: str) -> dict:
    """
    Analyse comportementale d'une image Docker via Falco modern_ebpf
    dans une microVM Firecracker isolée.

    Détecte : modifications fichiers système, connexions sortantes,
    fork bombs, évasion container, lecture credentials, cryptominers.

    Args:
        image: Nom Docker complet (ex: "nginx:alpine", "python:3.11")

    Returns:
        dict contenant :
          - score (int 0-100)
          - verdict (str : CLEAN | LOW | MODERATE | HIGH | CRITICAL)
          - allowed (bool)
          - critical (bool)
          - rule_counts (dict : règle → nombre d'alertes)
          - details (list : alertes détaillées)
    """
    SCAN_SCRIPT = "/home/mendy/Documents/DocDockGo/DockDockGo/docdockgo-scan-dynamique/scan_vm.sh"

    result = subprocess.run(
        ["sudo", "-n", "bash", SCAN_SCRIPT, image, "--details"],
        capture_output=True,
        text=True,
        timeout=300,
    )

    output = result.stdout
    start = output.find('{')
    end = output.rfind('}') + 1

    if start == -1 or end == 0:
        return {
            "image": image,
            "verdict": "ERROR",
            "error": "Pas de résultat JSON",
        }

    return json.loads(output[start:end])


if __name__ == "__main__":
    mcp.run()
```

### Méthode 2 — Appel direct subprocess

```python
import subprocess
import json

def scan_image(image: str) -> dict:
    """Scanne une image Docker via DockDockGo."""
    result = subprocess.run(
        ["sudo", "-n", "bash",
         "/path/to/docdockgo-scan-dynamique/scan_vm.sh",
         image, "--details"],
        capture_output=True, text=True, timeout=300,
    )
    output = result.stdout
    start = output.find('{')
    end = output.rfind('}') + 1
    return json.loads(output[start:end])

# Utilisation par l'IA décisionnaire
result = scan_image("nginx:alpine")

if result["allowed"]:
    print(f"✓ {result['image']} approuvée (score {result['score']})")
    # → autoriser le pull
else:
    print(f"✗ {result['image']} BLOQUÉE — verdict: {result['verdict']}")
    print(f"  Règles déclenchées :")
    for rule, count in result["rule_counts"].items():
        print(f"    - {rule} × {count}")
    # → bloquer le pull et alerter
```

### Méthode 3 — Appel HTTP

```python
import requests

def scan_via_http(image: str) -> dict:
    response = requests.post(
        "http://localhost:8080/scan",
        json={"image": image, "mode": "vm"},
        timeout=300,
    )
    return response.json()
```

---

## Format du résultat JSON

### Exemple de réponse

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
    "DDG Mount Attempt": 36,
    "DDG Shell Spawn": 2,
    "DDG Outbound Connection": 2,
    "DDG Sensitive File Access": 1,
    "DDG Suspicious Network Tool": 1
  },
  "details": [
    "[DDG] Shell spawned (command=sh -c ...)",
    "[DDG] Sensitive file accessed (file=/etc/passwd ...)",
    "[DDG] Outbound connection attempt (command=nslookup ...)",
    "[DDG] System file modification (file=/etc/passwd ...)"
  ]
}
```

### Description des champs

| Champ | Type | Description |
|-------|------|-------------|
| `image` | string | Nom de l'image scannée |
| `score` | int 0-100 | Score de menace agrégé |
| `critical` | bool | Au moins une règle critique déclenchée |
| `verdict` | string | Catégorie globale |
| `allowed` | bool | `true` si l'image peut être autorisée |
| `mode` | string | `vm` ou `docker` |
| `rule_counts` | dict | Nombre d'alertes par règle |
| `details` | list | Échantillon des alertes complètes |

### Décision par score

| Score | Verdict | Allowed | Action recommandée |
|-------|---------|---------|---------------------|
| 0 | `CLEAN` | ✅ true | Image autorisée |
| 1-29 | `LOW` | ✅ true | Image autorisée, log warning |
| 30-59 | `MODERATE` | ✅ true | Analyse manuelle conseillée |
| 60-89 | `HIGH` | ❌ false | Image bloquée |
| 90-100 | `CRITICAL` | ❌ false | Image bloquée + alerte |

> Le champ `allowed` passe à `false` aussi si `critical == true`, peu importe le score.

---

## Règles de détection

18 règles Falco organisées en **9 catégories MITRE ATT&CK** :

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

Voir [`falco_rules.local.yaml`](./falco_rules.local.yaml) pour le détail.

---

## Tests

### Image légitime → CLEAN attendu

```bash
sudo bash scan_vm.sh python:3.11-slim
# → Score 0/100, Verdict CLEAN, allowed=true
```

### Image malveillante → CRITICAL attendu

Le projet inclut un Dockerfile `dockdockgo-evil` qui simule plusieurs comportements malveillants (modification `/etc/passwd`, nslookup, mount tmpfs, fork loop, lecture `/etc/shadow`).

```bash
sudo bash scan_vm.sh dockdockgo-evil --details
# → Score 100/100, Verdict CRITICAL, allowed=false
```

---

## Désactiver l'automatisation

Pour retirer le sudoers NOPASSWD :

```bash
sudo rm /etc/sudoers.d/dockdockgo-mcp
```

---

## Structure du projet

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
├── Cargo.toml
├── install.sh                     # Setup Falco hôte (mode Docker direct)
├── setup_firecracker.sh           # Setup microVM complet
├── scan_vm.sh                     # Lance un scan dans la VM
└── setup_mcp_automation.sh        # Sudoers NOPASSWD pour MCP
```
