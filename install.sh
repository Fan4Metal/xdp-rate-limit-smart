#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then
  echo "Usage: sudo ./install.sh <interface>" >&2
  echo "Example: sudo ./install.sh eth0" >&2
  exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo ./install.sh $IFACE" >&2
  exit 1
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "Interface not found: $IFACE" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y clang llvm gcc make libbpf-dev libelf-dev zlib1g-dev iproute2 python3

mkdir -p /usr/local/lib/xdp-rate-limit /usr/local/sbin /etc/xdp-rate-limit /sys/fs/bpf/xdp-rate-limit
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

ARCH="$(uname -m)"
TARGET_ARCH="x86"
case "$ARCH" in
  x86_64|amd64) TARGET_ARCH="x86" ;;
  aarch64|arm64) TARGET_ARCH="arm64" ;;
  armv7l|armv8l|arm) TARGET_ARCH="arm" ;;
  ppc64le) TARGET_ARCH="powerpc" ;;
  s390x) TARGET_ARCH="s390" ;;
  *) echo "Unsupported arch for __TARGET_ARCH: $ARCH" >&2; exit 1 ;;
esac

MULTIARCH="$(gcc -print-multiarch 2>/dev/null || true)"
INCLUDE_ARGS=()
if [[ -n "$MULTIARCH" && -d "/usr/include/$MULTIARCH" ]]; then
  INCLUDE_ARGS+=("-I/usr/include/$MULTIARCH")
fi

clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_${TARGET_ARCH} "${INCLUDE_ARGS[@]}" \
  -c src/xdp_rate_limit.bpf.c \
  -o /usr/local/lib/xdp-rate-limit/xdp_rate_limit.bpf.o

gcc -O2 -g -Wall src/xdp_loader.c -o /usr/local/sbin/xdp-rate-loader -lbpf -lelf -lz
install -m 0755 src/xdp_rate_daemon.py /usr/local/sbin/xdp-rate-daemon
install -m 0755 src/xdp-rate-limit-wrapper /usr/local/sbin/xdp-rate-limit-wrapper
install -m 0644 systemd/xdp-rate-limit@.service /etc/systemd/system/xdp-rate-limit@.service

if [[ ! -f /etc/xdp-rate-limit/config.json ]]; then
  cp etc/config.json /etc/xdp-rate-limit/config.json

  # Try to protect the current SSH client automatically.
  SSH_CONN="${SSH_CONNECTION:-}"
  SSH_IP="${SSH_CONN%% *}"
  if [[ -n "$SSH_CONN" && "$SSH_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    python3 - "$SSH_IP" <<'PY'
import json, sys
path = "/etc/xdp-rate-limit/config.json"
ip = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    cfg = json.load(f)
wl = cfg.setdefault("whitelist", [])
if ip not in wl:
    wl.append(ip)
with open(path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
    echo "Added current SSH client to whitelist: $SSH_IP"
  fi
else
  echo "Keeping existing /etc/xdp-rate-limit/config.json"
fi

systemctl daemon-reload
systemctl enable --now "xdp-rate-limit@${IFACE}.service"

echo
echo "Installed and started: xdp-rate-limit@${IFACE}.service"
echo "Config: /etc/xdp-rate-limit/config.json"
echo "Logs: journalctl -u xdp-rate-limit@${IFACE} -f"
echo
echo "IMPORTANT: make sure your admin/SSH IP is in whitelist before lowering limits."
