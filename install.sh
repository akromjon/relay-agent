#!/usr/bin/env bash
# CHOP relay-agent installer. Run as root on Ubuntu/Debian. Idempotent.
#   ssh root@<relay> 'API_TOKEN=<token> bash -s' < install.sh
# Env: API_TOKEN (required on first install), RELAY_AGENT_PORT (8080),
#      RELAY_AGENT_VERSION (latest release tag), RELAY_AGENT_BINARY (local file, skips download)
set -Eeuo pipefail

REPO="akromjon/relay-agent"
BIN="/usr/local/bin/relay-agent"
ENV_DIR="/etc/relay-agent"
ENV_FILE="${ENV_DIR}/.env"
UNIT="/etc/systemd/system/relay-agent.service"
PORT="${RELAY_AGENT_PORT:-8080}"
NFT_CONF="/etc/nftables.conf"

log() { printf '[relay-agent] %s\n' "$*"; }
die() { printf '[relay-agent] ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "run as root"
command -v systemctl >/dev/null || die "systemd required"

# --- 1. packages -------------------------------------------------------------
if command -v apt-get >/dev/null; then
	need=()
	command -v nft >/dev/null || need+=(nftables)
	command -v conntrack >/dev/null || need+=(conntrack)
	command -v curl >/dev/null || need+=(curl)
	if ((${#need[@]})); then
		log "installing: ${need[*]}"
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}" >/dev/null
	fi
else
	log "no apt-get: install nftables + conntrack by hand, then re-run"
	command -v nft >/dev/null && command -v conntrack >/dev/null || die "nft/conntrack missing"
fi

# --- 2. relay prep (matches the fleet runbook) --------------------------------
cat > /etc/sysctl.d/99-chop-relay.conf <<'SYSCTL'
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_max = 262144
SYSCTL
echo nf_conntrack > /etc/modules-load.d/chop-relay.conf
modprobe nf_conntrack 2>/dev/null || true
sysctl -q --system >/dev/null

if [[ -f "${NFT_CONF}" ]] && grep -q 'chop_relay' "${NFT_CONF}"; then
	log "nftables.conf already has chop_relay - leaving it untouched"
else
	[[ -f "${NFT_CONF}" && ! -f "${NFT_CONF}.stock" ]] && cp "${NFT_CONF}" "${NFT_CONF}.stock"
	cat > "${NFT_CONF}" <<'NFT'
#!/usr/sbin/nft -f
table ip chop_relay
delete table ip chop_relay

table ip chop_relay {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
	}
}
NFT
	log "wrote empty chop_relay table to ${NFT_CONF}"
	nft -f "${NFT_CONF}"
fi
# Never reload an existing table: that resets counters and blinks live DNAT rules.
systemctl enable nftables >/dev/null 2>&1 || true
nft list table ip chop_relay >/dev/null 2>&1 || nft -f "${NFT_CONF}"

# --- 3. binary ----------------------------------------------------------------
case "$(uname -m)" in
	x86_64) ARCH=amd64 ;;
	aarch64|arm64) ARCH=arm64 ;;
	*) die "unsupported arch $(uname -m)" ;;
esac
TMP="$(mktemp -d)"; trap 'rm -rf "${TMP}"' EXIT
if [[ -n "${RELAY_AGENT_BINARY:-}" ]]; then
	cp "${RELAY_AGENT_BINARY}" "${TMP}/relay-agent"
else
	TAG="${RELAY_AGENT_VERSION:-$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)}"
	[[ -n "${TAG}" ]] || die "could not resolve latest release tag; set RELAY_AGENT_VERSION"
	BASE="https://github.com/${REPO}/releases/download/${TAG}"
	log "downloading ${TAG} (${ARCH})"
	curl -fsSL "${BASE}/relay-agent-linux-${ARCH}" -o "${TMP}/relay-agent"
	curl -fsSL "${BASE}/relay-agent-linux-${ARCH}.sha256" -o "${TMP}/sum"
	(cd "${TMP}" && sed "s#relay-agent-linux-${ARCH}#relay-agent#" sum | sha256sum -c --quiet -) || die "sha256 mismatch"
fi
install -m 0755 "${TMP}/relay-agent" "${BIN}"

# --- 4. env -------------------------------------------------------------------
mkdir -p "${ENV_DIR}"
if [[ -f "${ENV_FILE}" && -z "${API_TOKEN:-}" ]]; then
	log "keeping existing ${ENV_FILE}"
else
	[[ -n "${API_TOKEN:-}" ]] || die "API_TOKEN required on first install"
	umask 077
	cat > "${ENV_FILE}" <<ENV
API_TOKEN=${API_TOKEN}
RELAY_AGENT_PORT=${PORT}
ENV
	umask 022
	log "wrote ${ENV_FILE}"
fi

# --- 5. unit ------------------------------------------------------------------
SYSD_VER="$(systemctl --version | head -1 | awk '{print $2}')"
cat > "${UNIT}" <<'UNIT'
[Unit]
Description=CHOP relay agent (read-only stats)
Documentation=https://github.com/akromjon/relay-agent
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=/etc/relay-agent/.env
ExecStart=/usr/local/bin/relay-agent
Restart=on-failure
RestartSec=3
MemoryMax=32M
CPUQuota=10%
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
UNIT
if [[ "${SYSD_VER}" =~ ^[0-9]+$ ]] && ((SYSD_VER < 232)); then
	sed -i '/^MemoryMax=/d;/^CPUQuota=/d;/^ProtectSystem=strict/d' "${UNIT}"
	log "old systemd ${SYSD_VER}: dropped resource limits"
fi
systemctl daemon-reload
systemctl enable --now relay-agent >/dev/null
systemctl restart relay-agent

# --- 6. self-check ------------------------------------------------------------
TOKEN="$(sed -n 's/^API_TOKEN=//p' "${ENV_FILE}")"
for _ in 1 2 3 4 5; do
	if OUT="$(curl -fsS -m 3 -H "key: ${TOKEN}" "http://127.0.0.1:${PORT}/api/health" 2>/dev/null)" && [[ "${OUT}" == *'"running":true'* ]]; then
		log "OK ${OUT}"
		exit 0
	fi
	sleep 1
done
journalctl -u relay-agent -n 20 --no-pager >&2 || true
die "agent did not answer /api/health on :${PORT}"
