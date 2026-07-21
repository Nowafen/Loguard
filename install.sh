#!/usr/bin/env bash
# Loguard installer -- works across major Linux distributions.
#
# Usage:
#   sudo bash install.sh                     (from inside a cloned repo)
#   curl -fsSL <raw-url>/install.sh | sudo bash   (one-liner, downloads source)
#
# Non-interactive (Ansible/CI/Docker) install:
#   sudo LOGUARD_BOT_TOKEN=xxx LOGUARD_CHAT_ID=xxx LOGUARD_HOSTNAME=my-host bash install.sh
#
# What this does:
#   1. Detects your distro's package manager and init system.
#   2. Installs the small set of build dependencies needed (curl, a C/C++
#      compiler) -- Loguard itself has ZERO runtime library dependencies
#      beyond `curl` on the PATH, by design (see README "Why no libcurl").
#   3. Builds the two Loguard binaries from source.
#   4. Installs systemd units (or an OpenRC service + cron watchdog line
#      on non-systemd systems).
#   5. Detects this device's hostname/distro/architecture and asks you,
#      interactively, for your Telegram Bot Token and Chat ID.
#   6. Sends a real test message before enabling, so you know it works.
#   7. Enables monitoring (PAM hook + daemon + watchdog timer).

set -euo pipefail

REPO="Nowafen/Loguard"          # set to your actual GitHub owner/repo
BRANCH="main"
CLEANUP_DIRS=()

trap 'for d in "${CLEANUP_DIRS[@]:-}"; do [ -n "$d" ] && rm -rf "$d"; done' EXIT

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Please run as root (sudo bash install.sh)"

# ---------------------------------------------------------------------------
# 1. Detect distro + package manager
# ---------------------------------------------------------------------------
PKG_MGR=""
if   command -v apt-get >/dev/null 2>&1; then PKG_MGR="apt"
elif command -v dnf     >/dev/null 2>&1; then PKG_MGR="dnf"
elif command -v yum     >/dev/null 2>&1; then PKG_MGR="yum"
elif command -v zypper  >/dev/null 2>&1; then PKG_MGR="zypper"
elif command -v pacman  >/dev/null 2>&1; then PKG_MGR="pacman"
elif command -v apk     >/dev/null 2>&1; then PKG_MGR="apk"
else
    warn "Could not detect a known package manager (apt/dnf/yum/zypper/pacman/apk)."
    warn "Continuing anyway -- this only matters if curl/gcc/g++ are not already installed."
fi

DISTRO_PRETTY="Unknown Linux"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_PRETTY="${PRETTY_NAME:-$DISTRO_PRETTY}"
fi
ARCH="$(uname -m)"
HOSTNAME_DEFAULT="$(hostname 2>/dev/null || echo unknown-host)"

log "Detected: $DISTRO_PRETTY ($ARCH), package manager: ${PKG_MGR:-none}"

# ---------------------------------------------------------------------------
# 2. Detect init system
# ---------------------------------------------------------------------------
INIT_SYSTEM="none"
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    INIT_SYSTEM="systemd"
elif command -v rc-service >/dev/null 2>&1 || [ -d /etc/init.d ] && command -v openrc >/dev/null 2>&1; then
    INIT_SYSTEM="openrc"
elif [ -d /etc/init.d ]; then
    INIT_SYSTEM="sysvinit-cron"   # generic fallback: init.d exists but no openrc binary
fi
log "Init system: $INIT_SYSTEM"

# ---------------------------------------------------------------------------
# 3. Install build dependencies (curl + C/C++ toolchain)
# ---------------------------------------------------------------------------
install_deps() {
    if command -v curl >/dev/null 2>&1 && command -v g++ >/dev/null 2>&1 && command -v gcc >/dev/null 2>&1 && command -v make >/dev/null 2>&1; then
        log "curl/gcc/g++/make already present -- skipping package installation."
        return
    fi
    log "Installing dependencies (curl, gcc, g++, make)..."
    case "$PKG_MGR" in
        apt)
            apt-get update -y -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates gcc g++ make
            ;;
        dnf)    dnf install -y -q curl gcc gcc-c++ make ;;
        yum)    yum install -y -q curl gcc gcc-c++ make ;;
        zypper) zypper --non-interactive install curl gcc gcc-c++ make ;;
        pacman) pacman -Sy --noconfirm --needed curl gcc make ;;
        apk)    apk add --no-cache curl gcc g++ make musl-dev ;;
        *)
            command -v curl >/dev/null 2>&1 || die "curl is required and no package manager was detected -- install it manually."
            command -v g++  >/dev/null 2>&1 || die "g++ is required and no package manager was detected -- install it manually."
            ;;
    esac
}
install_deps

# ---------------------------------------------------------------------------
# 4. Get the source (use local checkout if the script is run from inside
#    the repo; otherwise download it)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
if [ -f "$SCRIPT_DIR/src/main.cpp" ]; then
    SRC_DIR="$SCRIPT_DIR"
    log "Using local source tree at $SRC_DIR"
else
    SRC_DIR="$(mktemp -d)"
    CLEANUP_DIRS+=("$SRC_DIR")
    log "Downloading source from https://github.com/$REPO ($BRANCH)..."
    if ! curl -fsSL "https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz" \
            | tar xz -C "$SRC_DIR" --strip-components=1; then
        die "Failed to download source. Check your network or clone the repo manually."
    fi
fi

# ---------------------------------------------------------------------------
# 5. Build
# ---------------------------------------------------------------------------
BUILD_DIR="$(mktemp -d)"
CLEANUP_DIRS+=("$BUILD_DIR")
log "Building Loguard from source..."
g++ -std=c++17 -O2 -o "$BUILD_DIR/loguard" \
    "$SRC_DIR"/src/main.cpp "$SRC_DIR"/src/util.cpp "$SRC_DIR"/src/config.cpp \
    "$SRC_DIR"/src/telegram.cpp "$SRC_DIR"/src/queue.cpp "$SRC_DIR"/src/pam.cpp \
    "$SRC_DIR"/src/integrity.cpp
gcc -O2 -o "$BUILD_DIR/loguard-notify" "$SRC_DIR"/src/pam_hook.c
log "Build succeeded."

# ---------------------------------------------------------------------------
# 6. Install files
# ---------------------------------------------------------------------------
log "Installing binaries and directories..."
install -d -m 0755 /opt/loguard/bin
install -m 0755 "$BUILD_DIR/loguard" /opt/loguard/bin/loguard
install -m 0755 "$BUILD_DIR/loguard-notify" /opt/loguard/bin/loguard-notify
ln -sf /opt/loguard/bin/loguard /usr/local/bin/loguard
install -d -m 0700 /etc/loguard
install -d -m 0700 /var/lib/loguard
install -d -m 0700 /var/log/loguard

case "$INIT_SYSTEM" in
    systemd)
        install -m 0644 "$SRC_DIR"/packaging/loguard.service /etc/systemd/system/loguard.service
        install -m 0644 "$SRC_DIR"/packaging/loguard-check.service /etc/systemd/system/loguard-check.service
        install -m 0644 "$SRC_DIR"/packaging/loguard-check.timer /etc/systemd/system/loguard-check.timer
        systemctl daemon-reload
        ;;
    openrc)
        install -m 0755 "$SRC_DIR"/packaging/openrc/loguard.init /etc/init.d/loguard
        (crontab -l 2>/dev/null | grep -v 'loguard check'; echo "* * * * * /opt/loguard/bin/loguard check >/dev/null 2>&1") | crontab -
        ;;
    sysvinit-cron)
        warn "No systemd/OpenRC detected. Installing a cron-based watchdog only."
        warn "You will need to start the daemon yourself, e.g. add to an init script:"
        warn "  /opt/loguard/bin/loguard daemon &"
        (crontab -l 2>/dev/null | grep -v 'loguard check'; echo "* * * * * /opt/loguard/bin/loguard check >/dev/null 2>&1") | crontab -
        ;;
    *)
        warn "No supported init system or cron detected."
        warn "Start the daemon manually: /opt/loguard/bin/loguard daemon &"
        ;;
esac

# ---------------------------------------------------------------------------
# 7. Gather device info + interactively collect Telegram credentials
# ---------------------------------------------------------------------------
echo
log "Telegram setup"
echo "  1) Message @BotFather on Telegram: /newbot   -> copy the Bot Token it gives you"
echo "  2) Start a chat with your new bot: /start"
echo "  3) Message @userinfobot to get your numeric Chat ID"
echo

read_tty() {
    local prompt="$1" default="${2:-}" var
    if [ -n "$default" ]; then
        read -r -p "$prompt [$default]: " var < /dev/tty || true
        echo "${var:-$default}"
    else
        read -r -p "$prompt: " var < /dev/tty || true
        echo "$var"
    fi
}

BOT_TOKEN="${LOGUARD_BOT_TOKEN:-}"
CHAT_ID="${LOGUARD_CHAT_ID:-}"
HOSTNAME_LABEL="${LOGUARD_HOSTNAME:-}"

if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
    log "Using Bot Token / Chat ID from LOGUARD_BOT_TOKEN / LOGUARD_CHAT_ID environment variables (non-interactive install)."
    HOSTNAME_LABEL="${HOSTNAME_LABEL:-$HOSTNAME_DEFAULT}"
else
    BOT_TOKEN="$(read_tty "Bot Token")"
    CHAT_ID="$(read_tty "Chat ID")"
    HOSTNAME_LABEL="$(read_tty "Device label to show in alerts" "$HOSTNAME_DEFAULT")"

    while [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; do
        warn "Both Bot Token and Chat ID are required to receive alerts."
        BOT_TOKEN="$(read_tty "Bot Token")"
        CHAT_ID="$(read_tty "Chat ID")"
    done
fi

cat > /etc/loguard/config.toml <<EOF
# Loguard configuration -- generated by install.sh on $(date '+%Y-%m-%d %H:%M:%S')
bot_token = "$BOT_TOKEN"
chat_id   = "$CHAT_ID"
hostname  = "$HOSTNAME_LABEL"
os_info   = "$DISTRO_PRETTY ($ARCH)"
heartbeat_minutes = 15
self_heal_pam = true
EOF
chmod 600 /etc/loguard/config.toml

# ---------------------------------------------------------------------------
# 8. Validate with a real test message, then enable
# ---------------------------------------------------------------------------
log "Sending a test message to confirm your credentials work..."
if /opt/loguard/bin/loguard test; then
    log "Test message delivered successfully."
else
    warn "Test message failed. Your credentials were saved, but nothing will be"
    warn "delivered until they're fixed. Re-run: sudo loguard edit && sudo loguard test"
fi

log "Enabling monitoring (PAM hook, daemon, watchdog timer)..."
/opt/loguard/bin/loguard enable

echo
log "Done! Run 'loguard status' any time to check health, or 'loguard help' for all commands."