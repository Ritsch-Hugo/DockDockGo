#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# scan_vm.sh — Scan microVM Firecracker
#
# Kernel 5.15 BTF + Falco modern_ebpf + Docker bridge
# Le scanner Rust crée lui-même le réseau ddg_analysis_net.
#
# Usage : sudo bash scan_vm.sh <image> [--details]
# ═══════════════════════════════════════════════════════════════

set -e

IMAGE="$1"
SHOW_DETAILS="${2:-}"

[[ -z "$IMAGE" ]] && {
    echo "Usage: sudo bash scan_vm.sh <image> [--details]"
    exit 1
}

FC_DIR="/opt/firecracker"
VM_SOCKET="/tmp/ddg-$(date +%s%N).sock"
VM_KEY="$FC_DIR/ddg-vm-key"
VM_IP="172.16.0.2"
TRANSFER_DIR="/tmp/ddg-transfer"

# ─────────────────────────────────────────────
# RÉSEAU TAP + NAT
# ─────────────────────────────────────────────
reset_network() {
    MAIN_IFACE=$(ip route show default | awk '{print $5}' | head -1)
    [[ -z "$MAIN_IFACE" ]] && {
        echo "[FC] ✗ Aucune interface réseau"
        exit 1
    }

    echo "[FC] Interface réseau : $MAIN_IFACE"

    ip link del ddg-tap0 2>/dev/null || true
    ip tuntap add dev ddg-tap0 mode tap
    ip addr add 172.16.0.1/24 dev ddg-tap0
    ip link set dev ddg-tap0 up
    echo 1 > /proc/sys/net/ipv4/ip_forward

    iptables -t nat -D POSTROUTING -o "$MAIN_IFACE" \
        -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i ddg-tap0 -o "$MAIN_IFACE" \
        -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$MAIN_IFACE" -o ddg-tap0 \
        -m state --state RELATED,ESTABLISHED \
        -j ACCEPT 2>/dev/null || true

    iptables -t nat -A POSTROUTING -o "$MAIN_IFACE" -j MASQUERADE
    iptables -A FORWARD -i ddg-tap0 -o "$MAIN_IFACE" -j ACCEPT
    iptables -A FORWARD -i "$MAIN_IFACE" -o ddg-tap0 \
        -m state --state RELATED,ESTABLISHED -j ACCEPT

    echo "[FC] Réseau TAP prêt → NAT via $MAIN_IFACE ✓"
}

# ─────────────────────────────────────────────
# API FIRECRACKER
# ─────────────────────────────────────────────
api() {
    curl -sf -X "$1" \
        --unix-socket "$VM_SOCKET" \
        -H "Content-Type: application/json" \
        ${3:+-d "$3"} \
        "http://localhost/$2" || true
}

# ─────────────────────────────────────────────
# SSH
# ─────────────────────────────────────────────
vm_ssh() {
    ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -o BatchMode=yes \
        -o ServerAliveInterval=10 \
        -o LogLevel=ERROR \
        -i "$VM_KEY" \
        root@"$VM_IP" "$@"
}

# ─────────────────────────────────────────────
# TRANSFERT IMAGE LOCALE
# ─────────────────────────────────────────────
transfer_local_image() {
    local image="$1"

    if ! docker image inspect "$image" &>/dev/null; then
        echo "[FC] Image non locale → pull dans la VM"
        return 0
    fi

    echo "[FC] Image locale détectée : $image"
    echo "[FC] Export + transfert..."

    local safe_name
    safe_name=$(echo "$image" | tr '/:' '--')
    local tar_path="$TRANSFER_DIR/${safe_name}.tar"

    mkdir -p "$TRANSFER_DIR"

    docker save "$image" -o "$tar_path"
    echo "[FC] Export : $(du -sh "$tar_path" | cut -f1) ✓"

    scp \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -i "$VM_KEY" \
        "$tar_path" \
        root@"$VM_IP":/tmp/ddg-image.tar

    echo "[FC] Transfert OK ✓"

    vm_ssh "docker load -i /tmp/ddg-image.tar \
        && echo '[VM] Image chargée ✓' \
        && rm -f /tmp/ddg-image.tar"

    rm -f "$tar_path"
}

# ─────────────────────────────────────────────
# CLEANUP
# ─────────────────────────────────────────────
cleanup() {
    echo "[FC] Extinction VM..."
    api PUT "actions" '{"action_type": "SendCtrlAltDel"}' 2>/dev/null || true
    sleep 2
    kill "$FC_PID" 2>/dev/null || true
    rm -f "$VM_SOCKET"
    rm -rf "$TRANSFER_DIR"
    echo "[FC] VM détruite ✓"
}
trap cleanup EXIT

reset_network

echo ""
echo "══════════════════════════════════════"
echo "  DockDockGo Firecracker Scan"
echo "  Image : $IMAGE"
echo "══════════════════════════════════════"

# ── Démarre Firecracker ──
firecracker --api-sock "$VM_SOCKET" &>/tmp/fc-log.txt &
FC_PID=$!
sleep 0.3

echo "[FC] Configuration VM..."

api PUT "boot-source" "{
    \"kernel_image_path\": \"$FC_DIR/vmlinux\",
    \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off ip=${VM_IP}::172.16.0.1:255.255.255.0::eth0:off\"
}"

api PUT "drives/rootfs" "{
    \"drive_id\": \"rootfs\",
    \"path_on_host\": \"$FC_DIR/ddg-rootfs.ext4\",
    \"is_root_device\": true,
    \"is_read_only\": false
}"

api PUT "machine-config" '{
    "vcpu_count": 2,
    "mem_size_mib": 2048
}'

api PUT "network-interfaces/eth0" '{
    "iface_id": "eth0",
    "guest_mac": "AA:FC:00:00:00:01",
    "host_dev_name": "ddg-tap0"
}'

echo "[FC] Boot microVM..."
api PUT "actions" '{"action_type": "InstanceStart"}'

# ── Attend SSH ──
echo "[FC] Attente démarrage VM..."
T_START=$(date +%s)
READY=0
for i in $(seq 1 45); do
    if vm_ssh "echo ok" &>/dev/null; then
        T_END=$(date +%s)
        echo "[FC] VM prête en $((T_END - T_START))s ✓"
        READY=1
        break
    fi
    sleep 1
done

if [[ $READY -eq 0 ]]; then
    echo "[FC] ✗ VM non accessible après 45s"
    cat /tmp/fc-log.txt | tail -20
    exit 1
fi

# ── Configure Docker + démarre services ──
echo "[FC] Configuration Docker dans la VM..."
vm_ssh "bash -s" <<'REMOTE'
set -e

echo 1 > /proc/sys/net/ipv4/ip_forward

update-alternatives --set iptables \
    /usr/sbin/iptables-legacy 2>/dev/null || true
update-alternatives --set ip6tables \
    /usr/sbin/ip6tables-legacy 2>/dev/null || true

# Config Docker — bridge ACTIVÉ pour permettre le réseau ddg_analysis_net
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'DOCKERCONF'
{
  "iptables": false,
  "storage-driver": "overlay2",
  "exec-opts": ["native.cgroupdriver=cgroupfs"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
DOCKERCONF

# Nettoie dossiers Docker potentiellement corrompus
rm -rf /var/lib/docker/tmp-old 2>/dev/null || true
mkdir -p /var/lib/docker/tmp /var/lib/docker/runtimes

systemctl daemon-reload
systemctl restart docker || true

# Attend Docker
DOCKER_OK=0
for i in $(seq 1 20); do
    if docker info &>/dev/null; then
        echo "[VM] Docker OK en ${i}s ✓"
        DOCKER_OK=1
        break
    fi
    sleep 1
done

if [[ $DOCKER_OK -eq 0 ]]; then
    echo "[VM] Docker KO"
    journalctl -u docker -n 20 --no-pager 2>&1 || true
    exit 1
fi

# Vérifie que le bridge fonctionne
if ! docker network ls | grep -q bridge; then
    echo "[VM] ⚠️  Pas de réseau bridge — Docker mal configuré"
fi

# Vide le log Falco
> /var/log/falco.log

# Démarre Falco modern_ebpf
systemctl restart falco-ddg 2>/dev/null || true

FALCO_OK=0
for i in $(seq 1 10); do
    if systemctl is-active falco-ddg &>/dev/null; then
        echo "[VM] Falco actif en ${i}s ✓"
        FALCO_OK=1
        break
    fi
    sleep 1
done

if [[ $FALCO_OK -eq 0 ]]; then
    echo "[VM] ⚠️  Falco KO :"
    journalctl -u falco-ddg -n 10 --no-pager
fi

# Démarre scanner HTTP
systemctl start ddg-scanner || true
echo "[VM] Services démarrés ✓"
REMOTE

# ── Attend scanner HTTP ──
echo "[FC] Attente scanner HTTP..."
T_START=$(date +%s)
SCANNER_READY=0
for i in $(seq 1 60); do
    if vm_ssh "curl -sf http://localhost:3006/health" &>/dev/null; then
        T_END=$(date +%s)
        echo "[FC] Scanner prêt en $((T_END - T_START))s ✓"
        SCANNER_READY=1
        break
    fi
    sleep 1
done

if [[ $SCANNER_READY -eq 0 ]]; then
    echo "[FC] ✗ Scanner HTTP KO"
    vm_ssh "journalctl -u ddg-scanner -n 30 --no-pager" || true
    exit 1
fi

# ── Transfert image locale ──
transfer_local_image "$IMAGE"

# ── Lance le scan ──
echo "[FC] Lancement scan : $IMAGE"
echo "[FC] Analyse en cours..."
echo ""

T_SCAN_START=$(date +%s)

RESULT=$(vm_ssh \
    "curl -sf \
          --max-time 300 \
          -X POST http://localhost:3006/scan \
          -H 'Content-Type: application/json' \
          -d '{\"image\": \"$IMAGE\", \"mode\": \"docker\"}'")

T_SCAN_END=$(date +%s)
SCAN_DURATION=$((T_SCAN_END - T_SCAN_START))

# ── Résultat ──
echo "══ RÉSULTAT ($SCAN_DURATION secondes) ══════════════"
if [[ -n "$RESULT" ]]; then
    echo "$RESULT" | python3 -m json.tool 2>/dev/null || echo "$RESULT"

    SCORE=$(echo "$RESULT" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(d.get('score','?'))" 2>/dev/null || echo "?")
    VERDICT=$(echo "$RESULT" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(d.get('verdict','?'))" 2>/dev/null || echo "?")
    ALLOWED=$(echo "$RESULT" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(d.get('allowed','?'))" 2>/dev/null || echo "?")

    echo ""
    echo "  Score   : $SCORE/100"
    echo "  Verdict : $VERDICT"
    echo "  Autorisé: $ALLOWED"
    echo "  Durée   : ${SCAN_DURATION}s"
else
    echo "  ✗ Aucun résultat"
    vm_ssh "journalctl -u ddg-scanner -n 30 --no-pager" || true
fi
echo "══════════════════════════════════════"

# ── Logs Falco ──
echo ""
echo "══ LOGS FALCO ════════════════════════"

FALCO_STATUS=$(vm_ssh "systemctl is-active falco-ddg 2>&1" || echo "inactive")
echo "  Service : $FALCO_STATUS"

LOG_SIZE=$(vm_ssh "stat -c '%s' /var/log/falco.log 2>/dev/null || echo 0")
echo "  Log     : ${LOG_SIZE} octets"
echo ""

if [[ "$LOG_SIZE" -gt 0 ]]; then
    if [[ "$SHOW_DETAILS" == "--details" ]]; then
        vm_ssh "cat /var/log/falco.log 2>/dev/null | \
            python3 -c \"
import sys, json
from collections import Counter
lines = [l.strip() for l in sys.stdin if l.strip()]
if not lines:
    print('  Aucune alerte')
    sys.exit(0)

rules = Counter()
samples = {}
for line in lines:
    try:
        d = json.loads(line)
        rule = d.get('rule','?')
        out  = d.get('output','')[:140]
        rules[rule] += 1
        if rule not in samples:
            samples[rule] = (d.get('priority','?'), out)
    except: pass

print(f'  Total alertes : {sum(rules.values())}')
print()
for rule, count in rules.most_common():
    prio, out = samples[rule]
    print(f'  [{prio:8}] {rule} × {count}')
    print(f'             {out}')
    print()
\""
    else
        vm_ssh "cat /var/log/falco.log 2>/dev/null | \
            python3 -c \"
import sys, json
from collections import Counter
rules = Counter()
for line in sys.stdin:
    try:
        d = json.loads(line.strip())
        rules[d.get('rule','?')] += 1
    except: pass
if rules:
    print(f'  Total alertes : {sum(rules.values())}')
    for rule, count in rules.most_common():
        print(f'  • {rule} × {count}')
else:
    print('  Aucune alerte')
\""
    fi
else
    echo "  Aucune alerte Falco (log vide)"
    if [[ "$FALCO_STATUS" != "active" ]]; then
        echo ""
        echo "  ⚠️  Falco non actif :"
        vm_ssh "journalctl -u falco-ddg -n 10 --no-pager" 2>/dev/null || true
    fi
fi
echo "══════════════════════════════════════"