#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# setup_firecracker.sh — DockDockGo Firecracker Setup
#
# Kernel 5.15 BTF + Falco modern_ebpf + Docker bridge fonctionnel
#
# Usage : sudo env PATH=$PATH bash setup_firecracker.sh
# ═══════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

FC_DIR="/opt/firecracker"
ROOTFS="$FC_DIR/ddg-rootfs.ext4"
VMLINUX="$FC_DIR/vmlinux"
VM_KEY="$FC_DIR/ddg-vm-key"
MOUNT_DIR="/tmp/ddg-rootfs-mount"

SCANNER_PROJECT="$(find /home -name 'docdockgo-scan-dynamique' \
                  -type d 2>/dev/null | head -1)"

check_requirements() {
    log_info "Vérification prérequis..."
    [[ $EUID -ne 0 ]] && \
        log_error "Lancez avec : sudo env PATH=\$PATH bash setup_firecracker.sh"
    [[ ! -e /dev/kvm ]] && \
        log_error "/dev/kvm absent. Activez VT-x/AMD-V dans le BIOS."
    chmod 666 /dev/kvm
    command -v docker &>/dev/null || log_error "Docker non installé"

    if ! command -v cargo &>/dev/null; then
        CARGO_PATH="/home/$SUDO_USER/.cargo/bin/cargo"
        if [[ -f "$CARGO_PATH" ]]; then
            export PATH="/home/$SUDO_USER/.cargo/bin:$PATH"
        else
            log_error "Rust/Cargo non installé."
        fi
    fi

    command -v musl-gcc &>/dev/null || apt-get install -y -qq musl-tools

    if ! sudo -u "$SUDO_USER" \
        env PATH="/home/$SUDO_USER/.cargo/bin:$PATH" \
        rustup target list --installed 2>/dev/null \
        | grep -q "x86_64-unknown-linux-musl"; then
        sudo -u "$SUDO_USER" \
            env PATH="/home/$SUDO_USER/.cargo/bin:$PATH" \
            rustup target add x86_64-unknown-linux-musl
    fi

    command -v debootstrap &>/dev/null || apt-get install -y -qq debootstrap

    [[ -z "$SCANNER_PROJECT" ]] && log_error "Projet scanner non trouvé"

    mkdir -p "$FC_DIR"
    log_success "Prérequis OK"
}

install_firecracker() {
    log_info "Firecracker..."
    if command -v firecracker &>/dev/null; then
        log_warn "Déjà installé"
        return
    fi
    local arch version url
    arch=$(uname -m)
    version="v1.6.0"
    url="https://github.com/firecracker-microvm/firecracker/releases/download"
    url="${url}/${version}/firecracker-${version}-${arch}.tgz"
    wget -q --show-progress "$url" -O /tmp/fc.tgz
    tar xzf /tmp/fc.tgz -C /tmp
    mv "/tmp/release-${version}-${arch}/firecracker-${version}-${arch}" \
       /usr/local/bin/firecracker
    chmod +x /usr/local/bin/firecracker
    rm -rf /tmp/fc.tgz "/tmp/release-${version}-${arch}"
    log_success "Firecracker installé"
}

check_kernel() {
    log_info "Kernel..."
    if [[ ! -f "$VMLINUX" ]]; then
        log_error "Kernel absent : $VMLINUX

Le kernel doit être compilé avec :
  - CONFIG_VIRTIO_MMIO=y, CONFIG_VIRTIO_BLK=y
  - CONFIG_DEBUG_INFO_BTF=y (pahole 1.22 requis, pas 1.25+)
  - CONFIG_BPF_SYSCALL=y, CONFIG_FTRACE_SYSCALLS=y
  - CONFIG_CGROUPS=y, CONFIG_CGROUP_BPF=y, CONFIG_MEMCG=y"
    fi
    if readelf -S "$VMLINUX" 2>/dev/null | grep -q "\.BTF "; then
        log_success "Kernel BTF OK : $(du -sh $VMLINUX | cut -f1)"
    else
        log_warn "BTF non détecté"
    fi
}

generate_ssh_key() {
    if [[ -f "$VM_KEY" ]]; then
        log_warn "Clé SSH déjà présente"
        return
    fi
    ssh-keygen -t ed25519 -f "$VM_KEY" -N "" -C "ddg-firecracker"
    log_success "Clé SSH créée"
}

build_rootfs() {
    log_info "Construction rootfs (~15 min)..."
    if [[ -f "$ROOTFS" ]]; then
        log_warn "Rootfs déjà présent — supprime $ROOTFS pour reconstruire"
        return
    fi

    apt-get install -y -qq e2fsprogs
    mkdir -p "$MOUNT_DIR"

    log_info "Disque 10GB..."
    dd if=/dev/zero of="$ROOTFS" bs=1M count=10240 status=progress
    mkfs.ext4 -L ddg-rootfs "$ROOTFS"
    mount "$ROOTFS" "$MOUNT_DIR"

    log_info "Ubuntu 22.04..."
    debootstrap --arch=amd64 jammy "$MOUNT_DIR" \
        http://archive.ubuntu.com/ubuntu

    mkdir -p "$MOUNT_DIR/etc/systemd/network"
    cat > "$MOUNT_DIR/etc/systemd/network/20-eth.network" <<'EOF'
[Match]
Name=eth0

[Network]
Address=172.16.0.2/24
Gateway=172.16.0.1
DNS=8.8.8.8
EOF

    echo "/dev/vda / ext4 defaults,noatime 0 1" > "$MOUNT_DIR/etc/fstab"
    echo "ddg-scanner" > "$MOUNT_DIR/etc/hostname"

    mkdir -p "$MOUNT_DIR/etc/systemd/system/serial-getty@ttyS0.service.d"
    cat > "$MOUNT_DIR/etc/systemd/system/serial-getty@ttyS0.service.d/override.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I 115200 vt220
EOF

    mkdir -p "$MOUNT_DIR/root/.ssh"
    chmod 700 "$MOUNT_DIR/root/.ssh"
    cp "${VM_KEY}.pub" "$MOUNT_DIR/root/.ssh/authorized_keys"
    chmod 600 "$MOUNT_DIR/root/.ssh/authorized_keys"

    cp /etc/resolv.conf "$MOUNT_DIR/etc/resolv.conf"

    log_info "Docker + Falco..."
    chroot "$MOUNT_DIR" /bin/bash <<'CHROOT'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y \
    curl wget gnupg ca-certificates \
    openssh-server systemd \
    iproute2 iputils-ping iptables \
    kmod

systemctl enable systemd-networkd
systemctl enable ssh

update-alternatives --set iptables \
    /usr/sbin/iptables-legacy 2>/dev/null || true
update-alternatives --set ip6tables \
    /usr/sbin/ip6tables-legacy 2>/dev/null || true

curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /usr/share/keyrings/docker.gpg

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu jammy stable" \
    > /etc/apt/sources.list.d/docker.list

apt-get update -qq
apt-get install -y docker-ce docker-ce-cli containerd.io

# Config Docker — bridge ACTIVÉ pour permettre les réseaux custom
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'DOCKERCONF'
{
  "iptables": true,
  "storage-driver": "overlay2",
  "exec-opts": ["native.cgroupdriver=cgroupfs"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
DOCKERCONF

systemctl enable docker

# Falco
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
    | gpg --dearmor -o /usr/share/keyrings/falco.gpg

echo "deb [signed-by=/usr/share/keyrings/falco.gpg] \
https://download.falco.org/packages/deb stable main" \
    > /etc/apt/sources.list.d/falcosecurity.list

apt-get update -qq
FALCO_DRIVER_LOADER=no apt-get install -y falco || true

systemctl disable falco 2>/dev/null || true
systemctl disable falco-modern-bpf 2>/dev/null || true
systemctl disable falcoctl-artifact-follow 2>/dev/null || true

sed -i 's/^json_output:.*/json_output: true/' \
    /etc/falco/falco.yaml 2>/dev/null || true
sed -i 's/^json_include_output_property:.*/json_include_output_property: true/' \
    /etc/falco/falco.yaml 2>/dev/null || true
sed -i 's/^buffered_outputs:.*/buffered_outputs: false/' \
    /etc/falco/falco.yaml 2>/dev/null || true

touch /var/log/falco.log
chmod 644 /var/log/falco.log

echo "[✓] Docker + Falco installés"
CHROOT

    # Règles DDG
    log_info "Règles Falco DDG..."
    mkdir -p "$MOUNT_DIR/etc/falco/rules.d"
    cat > "$MOUNT_DIR/etc/falco/rules.d/ddg_rules.yaml" <<'RULES'
- rule: DDG Sensitive File Access
  desc: Detect sensitive file access inside container
  condition: >
    container and open_read and
    fd.name in (/etc/shadow, /etc/passwd, /etc/sudoers)
  output: >
    [DDG] Sensitive file accessed
    (file=%fd.name command=%proc.cmdline container=%container.name)
  priority: WARNING
  tags: [ddg, filesystem]

- rule: DDG Shell Spawn
  desc: Detect shell spawn inside container
  condition: >
    container and
    evt.type in (execve, execveat) and
    proc.name in (bash, sh, zsh, dash)
  output: >
    [DDG] Shell spawned
    (command=%proc.cmdline container=%container.name)
  priority: NOTICE
  tags: [ddg, execution]

- rule: DDG Outbound Connection
  desc: Detect outbound network connection from container
  condition: >
    container and
    evt.type = connect and
    fd.typechar = 4
  output: >
    [DDG] Outbound connection attempt
    (command=%proc.cmdline container=%container.name)
  priority: WARNING
  tags: [ddg, network]

- rule: DDG Fork Bomb Detection
  desc: Detect abnormal fork activity
  condition: >
    container and
    spawned_process and
    proc.nchilds > 20
  output: >
    [DDG] Possible fork anomaly
    (command=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [ddg, resource]

- rule: DDG Mount Attempt
  desc: Detect mount syscall from non-runtime process
  condition: >
    container and
    evt.type = mount and
    not proc.name in (runc, containerd-shim, containerd, docker)
  output: >
    [DDG] Mount attempt detected
    (command=%proc.cmdline container=%container.name)
  priority: WARNING
  tags: [ddg, privilege]

- rule: DDG System File Modification
  desc: Detect write to system account files
  condition: >
    container and
    evt.type in (open, openat) and
    evt.arg.flags contains O_WRONLY and
    fd.name in (/etc/passwd, /etc/shadow)
  output: >
    [DDG] System file modification
    (file=%fd.name command=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [ddg, persistence]
RULES

    # Service Falco modern_ebpf
    cat > "$MOUNT_DIR/etc/systemd/system/falco-ddg.service" <<'EOF'
[Unit]
Description=Falco DDG Runtime Security (modern_ebpf BTF)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/falco \
  -o engine.kind=modern_ebpf \
  -o json_output=true \
  -o json_include_output_property=true \
  -o file_output.enabled=true \
  -o file_output.filename=/var/log/falco.log \
  -o buffered_outputs=false
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    chroot "$MOUNT_DIR" systemctl enable falco-ddg 2>/dev/null || true

    log_info "Compilation scanner Rust (musl)..."
    sudo -u "$SUDO_USER" \
        env PATH="/home/$SUDO_USER/.cargo/bin:$PATH" \
        cargo build --release \
        --target x86_64-unknown-linux-musl \
        --manifest-path "$SCANNER_PROJECT/Cargo.toml"

    BINARY="$SCANNER_PROJECT/target/x86_64-unknown-linux-musl/release/docdockgo-scan-dynamique"
    cp "$BINARY" "$MOUNT_DIR/usr/local/bin/ddg-scanner"
    chmod +x "$MOUNT_DIR/usr/local/bin/ddg-scanner"

    cat > "$MOUNT_DIR/etc/systemd/system/ddg-scanner.service" <<'EOF'
[Unit]
Description=DockDockGo HTTP Scanner
After=docker.service network.target falco-ddg.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ddg-scanner --server
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    chroot "$MOUNT_DIR" systemctl enable ddg-scanner 2>/dev/null || true

    umount "$MOUNT_DIR"
    log_success "Rootfs construit"
}

setup_network() {
    log_info "Réseau TAP..."
    ip link del ddg-tap0 2>/dev/null || true

    cat > /etc/systemd/system/ddg-tap.service <<'EOF'
[Unit]
Description=DockDockGo TAP Network for Firecracker
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/bash -c 'ip link del ddg-tap0 2>/dev/null || true'
ExecStart=/sbin/ip tuntap add dev ddg-tap0 mode tap
ExecStart=/sbin/ip addr add 172.16.0.1/24 dev ddg-tap0
ExecStart=/sbin/ip link set dev ddg-tap0 up
ExecStart=/bin/bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
ExecStop=/sbin/ip link del ddg-tap0 2>/dev/null || true

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable ddg-tap
    systemctl start ddg-tap
    log_success "TAP : 172.16.0.1 ↔ 172.16.0.2"
}

main() {
    echo ""
    echo "══════════════════════════════════════════════"
    echo "  DockDockGo — Firecracker Setup"
    echo "══════════════════════════════════════════════"
    check_requirements
    install_firecracker
    check_kernel
    generate_ssh_key
    build_rootfs
    setup_network
    echo ""
    echo "══════════════════════════════════════════════"
    echo "  Setup terminé ✓"
    echo "  Test : sudo bash scan_vm.sh dockdockgo-evil --details"
    echo "══════════════════════════════════════════════"
}

main "$@"