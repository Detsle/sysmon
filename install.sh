#!/bin/sh
set -eu

APP_NAME="sysmon"
INSTALL_DIR="/opt/sysmon"
BIN_DIR="/usr/local/bin"
DATA_DIR="/var/lib/sysmon"
SYSTEMD_DIR="/etc/systemd/system"
CRON_BEGIN="# BEGIN SYSMON COLLECTOR"
CRON_END="# END SYSMON COLLECTOR"

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
SCRIPT_PATH="$SCRIPT_DIR/$(basename "$0")"
OS_NAME=$(uname -s 2>/dev/null || echo unknown)

say() { printf '%s\n' "$*"; }
fail() { say "ERROR: $*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo sh "$SCRIPT_PATH" "$@"
    elif command -v doas >/dev/null 2>&1; then
        exec doas sh "$SCRIPT_PATH" "$@"
    else
        fail "Run as root or install sudo/doas first."
    fi
fi

[ -f "$SCRIPT_DIR/sysmon.py" ] || fail "sysmon.py is missing. Run this installer from the cloned repository."

PACKAGE_MANAGER=""
if [ "$OS_NAME" = "Linux" ]; then
    if command -v apt-get >/dev/null 2>&1; then PACKAGE_MANAGER="apt-get"
    elif command -v dnf >/dev/null 2>&1; then PACKAGE_MANAGER="dnf"
    elif command -v yum >/dev/null 2>&1; then PACKAGE_MANAGER="yum"
    elif command -v apk >/dev/null 2>&1; then PACKAGE_MANAGER="apk"
    elif command -v pacman >/dev/null 2>&1; then PACKAGE_MANAGER="pacman"
    elif command -v zypper >/dev/null 2>&1; then PACKAGE_MANAGER="zypper"
    elif command -v emerge >/dev/null 2>&1; then PACKAGE_MANAGER="emerge"
    fi
elif [ "$OS_NAME" = "FreeBSD" ] || [ "$OS_NAME" = "DragonFly" ]; then
    if command -v pkg >/dev/null 2>&1; then PACKAGE_MANAGER="pkg"; fi
elif [ "$OS_NAME" = "OpenBSD" ]; then
    if command -v pkg_add >/dev/null 2>&1; then PACKAGE_MANAGER="pkg_add"; fi
elif [ "$OS_NAME" = "NetBSD" ]; then
    if command -v pkgin >/dev/null 2>&1; then PACKAGE_MANAGER="pkgin"
    elif command -v pkg_add >/dev/null 2>&1; then PACKAGE_MANAGER="pkg_add"
    fi
fi

find_python() {
    for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
            command -v "$candidate"
            return 0
        fi
        for candidate_path in "/usr/local/bin/$candidate" "/usr/pkg/bin/$candidate"; do
            if [ -x "$candidate_path" ] && "$candidate_path" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
                printf '%s\n' "$candidate_path"
                return 0
            fi
        done
    done
    return 1
}

install_python_runtime() {
    case "$OS_NAME:$PACKAGE_MANAGER" in
        Linux:apt-get)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y python3 python3-venv python3-pip
            ;;
        Linux:dnf) dnf install -y python3 python3-pip ;;
        Linux:yum) yum install -y python3 python3-pip ;;
        Linux:apk) apk add --no-cache python3 py3-pip ;;
        Linux:pacman) pacman -Sy --needed --noconfirm python python-pip ;;
        Linux:zypper) zypper --non-interactive install python3 python3-pip ;;
        Linux:emerge) emerge --ask=n dev-lang/python dev-python/pip ;;
        FreeBSD:pkg) pkg install -y python3 ;;
        OpenBSD:pkg_add) pkg_add -I python%3 py3-pip ;;
        NetBSD:pkgin) pkgin -y install python314 py314-pip ;;
        NetBSD:pkg_add) pkg_add python314 py314-pip ;;
        *)
            fail "Python 3.8+ is missing and no supported package manager was detected for $OS_NAME."
            ;;
    esac
}

install_build_dependencies() {
    say "A source build is required; installing build dependencies..."
    case "$OS_NAME:$PACKAGE_MANAGER" in
        Linux:apt-get)
            export DEBIAN_FRONTEND=noninteractive
            apt-get install -y python3-dev build-essential
            ;;
        Linux:dnf) dnf install -y python3-devel gcc make ;;
        Linux:yum) yum install -y python3-devel gcc make ;;
        Linux:apk) apk add --no-cache python3-dev gcc musl-dev linux-headers ;;
        Linux:pacman) pacman -S --needed --noconfirm base-devel ;;
        Linux:zypper) zypper --non-interactive install python3-devel gcc make ;;
        Linux:emerge) emerge --ask=n sys-devel/gcc ;;
        FreeBSD:pkg|DragonFly:pkg)
            # Clang and make are normally part of the base development toolchain.
            command -v cc >/dev/null 2>&1 || pkg install -y llvm
            ;;
        OpenBSD:pkg_add|NetBSD:pkgin|NetBSD:pkg_add)
            command -v cc >/dev/null 2>&1 || fail "A C compiler is required to build psutil on $OS_NAME."
            ;;
        *) fail "Could not install a compiler toolchain for $OS_NAME." ;;
    esac
}

say "[1/8] Detecting platform: $OS_NAME"
if ! PYTHON_BIN=$(find_python); then
    say "Python 3.8+ not found; installing the runtime..."
    install_python_runtime
    PYTHON_BIN=$(find_python) || fail "Python installation completed, but Python 3.8+ was not found."
else
    say "Python found: $PYTHON_BIN"
fi

say "[2/8] Preparing isolated Python environment"
mkdir -p "$INSTALL_DIR"
if [ ! -x "$INSTALL_DIR/venv/bin/python" ]; then
    if ! "$PYTHON_BIN" -m venv "$INSTALL_DIR/venv" >/dev/null 2>&1; then
        install_python_runtime
        PYTHON_BIN=$(find_python) || fail "Python installation completed, but Python 3.8+ was not found."
        rm -rf "$INSTALL_DIR/venv"
        if ! "$PYTHON_BIN" -m venv "$INSTALL_DIR/venv" >/dev/null 2>&1; then
            # Some OS Python builds ship pip as a separate system package and omit ensurepip.
            # In that case, expose system packages to the venv but keep Sysmon packages isolated.
            rm -rf "$INSTALL_DIR/venv"
            "$PYTHON_BIN" -m venv --system-site-packages --without-pip "$INSTALL_DIR/venv" || fail "Could not create a virtual environment. Install the OS venv package."
        fi
    fi
else
    "$INSTALL_DIR/venv/bin/python" -m venv --upgrade "$INSTALL_DIR/venv" >/dev/null 2>&1 || :
fi
VENV_PYTHON="$INSTALL_DIR/venv/bin/python"
[ -x "$VENV_PYTHON" ] || fail "Virtual environment Python was not created."
"$VENV_PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' || fail "Sysmon requires Python 3.8 or newer."

say "[3/8] Installing psutil"
if ! "$VENV_PYTHON" -m pip --version >/dev/null 2>&1; then
    "$VENV_PYTHON" -m ensurepip --upgrade >/dev/null 2>&1 || :
fi
if ! "$VENV_PYTHON" -m pip --version >/dev/null 2>&1; then
    install_python_runtime
    PYTHON_BIN=$(find_python) || fail "Python 3.8+ was not found after installing pip."
    rm -rf "$INSTALL_DIR/venv"
    "$PYTHON_BIN" -m venv --system-site-packages --without-pip "$INSTALL_DIR/venv" || fail "Could not create a venv that uses the OS-provided pip package."
    VENV_PYTHON="$INSTALL_DIR/venv/bin/python"
fi
"$VENV_PYTHON" -m pip --version >/dev/null 2>&1 || fail "pip is unavailable. Install the OS pip package and rerun the installer."
if ! "$VENV_PYTHON" -m pip install --disable-pip-version-check --no-input psutil; then
    install_build_dependencies
    "$VENV_PYTHON" -m pip install --disable-pip-version-check --no-input psutil || fail "Could not install psutil. Check network access and Python build dependencies."
fi
"$VENV_PYTHON" -c 'import curses, psutil' || fail "Python must provide both curses and psutil. Install a Python build with curses support."

say "[4/8] Installing Sysmon"
cp "$SCRIPT_DIR/sysmon.py" "$INSTALL_DIR/sysmon.py"
chmod 755 "$INSTALL_DIR/sysmon.py"
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/sysmon" <<EOF
#!/bin/sh
exec "$VENV_PYTHON" "$INSTALL_DIR/sysmon.py" "\$@"
EOF
chmod 755 "$BIN_DIR/sysmon"
mkdir -p "$DATA_DIR"
chmod 755 "$DATA_DIR"

say "[5/8] Initializing outbound traffic accounting"
"$BIN_DIR/sysmon" --collect

install_systemd_timer() {
    mkdir -p "$SYSTEMD_DIR"
    cat > "$SYSTEMD_DIR/sysmon-collector.service" <<EOF
[Unit]
Description=Sysmon outbound traffic collector
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$VENV_PYTHON $INSTALL_DIR/sysmon.py --collect
User=root
Group=root
StandardOutput=null
EOF
    cat > "$SYSTEMD_DIR/sysmon-collector.timer" <<'EOF'
[Unit]
Description=Run Sysmon outbound traffic collector every minute

[Timer]
OnBootSec=20s
OnUnitActiveSec=60s
AccuracySec=5s
Unit=sysmon-collector.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now sysmon-collector.timer
    systemctl is-active --quiet sysmon-collector.timer || fail "systemd timer could not be activated."
    say "Background collector: systemd timer (60 seconds)"
}

install_cron_job() {
    if ! command -v crontab >/dev/null 2>&1; then
        case "$OS_NAME:$PACKAGE_MANAGER" in
            Linux:apt-get) apt-get install -y cron ;;
            Linux:dnf) dnf install -y cronie ;;
            Linux:yum) yum install -y cronie ;;
            Linux:apk) apk add --no-cache dcron ;;
            Linux:pacman) pacman -S --needed --noconfirm cronie ;;
            Linux:zypper) zypper --non-interactive install cron ;;
            Linux:emerge) emerge --ask=n sys-process/cronie ;;
            *) fail "crontab is unavailable on $OS_NAME. Install a cron implementation and rerun." ;;
        esac
    fi
    command -v crontab >/dev/null 2>&1 || fail "crontab command is still unavailable."

    current=$(mktemp "${TMPDIR:-/tmp}/sysmon.current.XXXXXX")
    cleaned=$(mktemp "${TMPDIR:-/tmp}/sysmon.cleaned.XXXXXX")
    updated=$(mktemp "${TMPDIR:-/tmp}/sysmon.updated.XXXXXX")
    trap 'rm -f "$current" "$cleaned" "$updated"' 0 HUP INT TERM
    crontab -l > "$current" 2>/dev/null || :
    awk -v begin="$CRON_BEGIN" -v end="$CRON_END" '
        $0 == begin { skip = 1; next }
        $0 == end { skip = 0; next }
        !skip { print }
    ' "$current" > "$cleaned"
    cat "$cleaned" > "$updated"
    {
        printf '%s\n' "$CRON_BEGIN"
        printf '* * * * * %s %s --collect >/dev/null 2>&1\n' "$VENV_PYTHON" "$INSTALL_DIR/sysmon.py"
        printf '%s\n' "$CRON_END"
    } >> "$updated"
    crontab "$updated"
    rm -f "$current" "$cleaned" "$updated"
    trap - 0 HUP INT TERM

    case "$OS_NAME" in
        Linux)
            if command -v rc-service >/dev/null 2>&1; then
                command -v rc-update >/dev/null 2>&1 && rc-update add crond default >/dev/null 2>&1 || :
                rc-service crond start >/dev/null 2>&1 || fail "Could not start crond."
            elif command -v service >/dev/null 2>&1; then
                service cron start >/dev/null 2>&1 || service crond start >/dev/null 2>&1 || fail "Could not start cron/crond."
            elif [ -x /etc/init.d/cron ]; then
                /etc/init.d/cron start >/dev/null 2>&1 || fail "Could not start cron."
            elif [ -x /etc/init.d/crond ]; then
                /etc/init.d/crond start >/dev/null 2>&1 || fail "Could not start crond."
            else
                fail "Cron job installed, but no supported cron service manager was found."
            fi
            ;;
        FreeBSD|DragonFly)
            command -v sysrc >/dev/null 2>&1 && sysrc cron_enable=YES >/dev/null 2>&1 || :
            command -v service >/dev/null 2>&1 && service cron start >/dev/null 2>&1 || fail "Could not start cron."
            ;;
        OpenBSD)
            command -v rcctl >/dev/null 2>&1 || fail "rcctl is unavailable; cannot enable cron."
            rcctl enable cron >/dev/null 2>&1 || fail "Could not enable cron."
            rcctl start cron >/dev/null 2>&1 || fail "Could not start cron."
            ;;
        NetBSD)
            if [ -x /etc/rc.d/cron ]; then
                grep -q '^cron=YES' /etc/rc.conf 2>/dev/null || printf '\ncron=YES\n' >> /etc/rc.conf
                /etc/rc.d/cron start >/dev/null 2>&1 || fail "Could not start cron."
            else
                fail "NetBSD cron service script was not found."
            fi
            ;;
        *) fail "Cron scheduler is not configured for $OS_NAME." ;;
    esac
    say "Background collector: cron (every minute)"
}

say "[6/8] Configuring background collection"
if [ "$OS_NAME" = "Linux" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    install_systemd_timer
else
    install_cron_job
fi

say "[7/8] Verifying installation"
"$BIN_DIR/sysmon" --collect >/dev/null
"$BIN_DIR/sysmon" --version
[ -s "$DATA_DIR/traffic.json" ] || fail "Traffic data file was not created."

say "[8/8] Installation complete"
say "Run: sysmon"
say "Traffic data: $DATA_DIR/traffic.json"
say "Set a traffic quota: sysmon --set-limit 2TB"
say "Set a specific interface: sysmon --interface eth0"
