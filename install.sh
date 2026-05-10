#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOURCE="$SCRIPT_DIR/sysmon.py"
INSTALL_DIR="/opt/sysmon"
TARGET="$INSTALL_DIR/sysmon.py"
LINK="/usr/local/bin/sysmon"

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  SUDO="sudo"
fi

if [ ! -f "$SOURCE" ]; then
  echo "Error: $SOURCE not found. Run install.sh from the repository root."
  exit 1
fi

HAS_APT=0
if command -v apt >/dev/null 2>&1; then
  HAS_APT=1
fi

if ! command -v python3 >/dev/null 2>&1; then
  if [ "$HAS_APT" -eq 1 ]; then
    echo "[1/6] Installing python3..."
    $SUDO apt update
    $SUDO apt install -y python3
  else
    echo "Error: python3 not found and apt unavailable."
    exit 1
  fi
fi

if ! command -v pip3 >/dev/null 2>&1; then
  if [ "$HAS_APT" -eq 1 ]; then
    echo "[2/6] Installing python3-pip..."
    $SUDO apt install -y python3-pip
  else
    echo "Error: pip3 not found and apt unavailable."
    exit 1
  fi
fi

echo "[3/6] Ensuring psutil..."
if python3 -c "import psutil" >/dev/null 2>&1; then
  echo "[3/6] psutil already installed"
else
  if [ "$HAS_APT" -eq 1 ]; then
    if $SUDO apt install -y python3-psutil >/dev/null 2>&1; then
      echo "[3/6] psutil installed via apt"
    else
      pip3 install --user psutil
      echo "[3/6] psutil installed via pip3 (user)"
    fi
  else
    pip3 install --user psutil
    echo "[3/6] psutil installed via pip3 (user)"
  fi
fi

echo "[4/6] Installing files..."
$SUDO mkdir -p "$INSTALL_DIR"
$SUDO cp -f "$SOURCE" "$TARGET"
$SUDO chown root:root "$TARGET"

if ! head -n 1 "$TARGET" | grep -qE '^#!.*python3'; then
  $SUDO sed -i '1i #!/usr/bin/env python3' "$TARGET"
fi

echo "[5/6] Making executable..."
$SUDO chmod +x "$TARGET"

echo "[6/6] Creating symlink..."
$SUDO rm -f "$LINK"
$SUDO ln -s "$TARGET" "$LINK"
$SUDO chmod +x "$TARGET"

echo "✅ Установка завершена."
echo "Запуск: sysmon"
