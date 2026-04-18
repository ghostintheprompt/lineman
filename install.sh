#!/bin/bash
# install.sh — Lineman HIPS Installer
# =====================================
# Must run as root: sudo bash install.sh
#
# What this script does:
#   1. Copies the daemon and GUI to /usr/local/lineman/
#   2. Installs the launchd plist to /Library/LaunchDaemons/
#   3. Creates the pf anchor file
#   4. Patches /etc/pf.conf with the anchor reference (idempotent)
#   5. Loads the daemon service via launchctl
#   6. Verifies the daemon is responsive

set -euo pipefail

INSTALL_DIR="/usr/local/lineman"
PLIST_SRC="com.lineman.daemon.plist"
PLIST_DST="/Library/LaunchDaemons/com.lineman.daemon.plist"
ANCHOR_NAME="com.lineman.blocker"
ANCHOR_FILE="/etc/pf.anchors/${ANCHOR_NAME}"
PF_CONF="/etc/pf.conf"
FORENSICS_DIR="${INSTALL_DIR}/forensics"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC}  $*"; }
warn() { echo -e "${YELLOW}  ⚠${NC}  $*"; }
fail() { echo -e "${RED}  ✗${NC}  $*"; exit 1; }
step() { echo -e "\n${YELLOW}──${NC} $*"; }

# ── Pre-flight ────────────────────────────────────────────────────────────────
[[ $(id -u) -eq 0 ]] || fail "Run as root: sudo bash install.sh"

step "Checking dependencies"
command -v python3  >/dev/null 2>&1 || fail "python3 not found"
command -v pfctl    >/dev/null 2>&1 || fail "pfctl not found (not macOS?)"
command -v tcpdump  >/dev/null 2>&1 || fail "tcpdump not found"
command -v launchctl >/dev/null 2>&1 || fail "launchctl not found (not macOS?)"
ok "All dependencies present"

# Check Python psutil (optional but recommended for legacy monitor_connections)
python3 -c "import psutil" 2>/dev/null && ok "psutil available" \
    || warn "psutil not installed — some features limited (pip3 install psutil)"

# ── Install files ─────────────────────────────────────────────────────────────
step "Installing files to ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}" "${FORENSICS_DIR}"

cp -R lineman-daemon/ "${INSTALL_DIR}/lineman-daemon/"
cp -R lineman-gui/    "${INSTALL_DIR}/lineman-gui/"
chmod 750 "${INSTALL_DIR}/lineman-daemon/daemon.py"
chmod 750 "${INSTALL_DIR}/lineman-gui/app.py"
ok "Files installed"

# ── pf anchor ─────────────────────────────────────────────────────────────────
step "Installing pf anchor"

cat > "${ANCHOR_FILE}" << 'ANCHOR_EOF'
# Lineman HIPS — managed by lineman-daemon. DO NOT EDIT MANUALLY.
table <lineman_blocked> persist {}
block drop out log quick proto tcp from any to <lineman_blocked>
block drop out log quick proto udp from any to <lineman_blocked>
ANCHOR_EOF
chmod 644 "${ANCHOR_FILE}"
ok "Anchor file written: ${ANCHOR_FILE}"

# Patch pf.conf — idempotent
if grep -q "${ANCHOR_NAME}" "${PF_CONF}"; then
    ok "pf.conf already has anchor reference — skipping patch"
else
    cat >> "${PF_CONF}" << PFEOF

# --- Lineman HIPS anchor (managed) ---
anchor "${ANCHOR_NAME}"
load anchor "${ANCHOR_NAME}" from "${ANCHOR_FILE}"
PFEOF
    ok "pf.conf patched"
fi

# Enable pf and reload
pfctl -e 2>/dev/null || true
pfctl -f "${PF_CONF}" && ok "pf reloaded" || warn "pf reload returned non-zero (may be harmless)"

# ── launchd plist ─────────────────────────────────────────────────────────────
step "Installing launchd service"

# Update install path in plist
sed "s|/usr/local/lineman|${INSTALL_DIR}|g" "${PLIST_SRC}" > "${PLIST_DST}"
chmod 644 "${PLIST_DST}"
chown root:wheel "${PLIST_DST}"
ok "Plist installed: ${PLIST_DST}"

# Unload if already loaded
launchctl unload "${PLIST_DST}" 2>/dev/null || true
launchctl load -w "${PLIST_DST}" && ok "Daemon service loaded" || fail "launchctl load failed"

# ── Verify ────────────────────────────────────────────────────────────────────
step "Verifying daemon"
sleep 2   # give it a moment to start

SOCKET_RESPONSE=$(python3 -c "
import socket, json
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect('/var/run/lineman.sock')
    s.sendall(b'{\"action\":\"ping\"}\n')
    data = s.recv(1024)
    s.close()
    r = json.loads(data)
    print('ok' if r.get('status') == 'ok' else 'fail')
except Exception as e:
    print(f'fail: {e}')
" 2>&1)

if [[ "${SOCKET_RESPONSE}" == "ok" ]]; then
    ok "Daemon is responsive on /var/run/lineman.sock"
else
    warn "Daemon ping failed: ${SOCKET_RESPONSE}"
    warn "Check logs: tail -f /var/log/lineman-daemon-error.log"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Lineman HIPS installed successfully   ${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "  Daemon:     launchd service com.lineman.daemon (root)"
echo "  Anchor:     ${ANCHOR_FILE}"
echo "  Socket:     /var/run/lineman.sock"
echo "  Forensics:  ${FORENSICS_DIR}"
echo "  Logs:       /var/log/lineman-daemon.log"
echo ""
echo "  Start GUI:  python3 ${INSTALL_DIR}/lineman-gui/app.py"
echo ""
echo "  To uninstall:"
echo "    sudo launchctl unload ${PLIST_DST}"
echo "    sudo python3 ${INSTALL_DIR}/lineman-daemon/daemon.py --uninstall"
echo ""
