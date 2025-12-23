#!/usr/bin/env bash
set -euo pipefail

TARGET="$HOME/sysmon.py"
LINK="/usr/local/bin/sysmon"

echo "[1/5] Проверка Python3..."
if ! command -v python3 >/dev/null 2>&1; then
  echo "Устанавливаю python3..."
  sudo apt update && sudo apt install -y python3
fi

echo "[2/5] Проверка pip..."
if ! command -v pip3 >/dev/null 2>&1; then
  echo "Устанавливаю python3-pip..."
  sudo apt install -y python3-pip
fi

echo "[3/5] Установка psutil..."
if command -v apt >/dev/null 2>&1; then
  if sudo apt install -y python3-psutil; then
    echo "psutil установлен через apt."
  else
    echo "apt не смог поставить psutil, пробую pip..."
    python3 -m pip install --user psutil --break-system-packages
  fi
else
  python3 -m pip install --user psutil --break-system-packages
fi

echo "[4/5] Копирую sysmon.py..."
cp ./sysmon.py "$TARGET"
chmod +x "$TARGET"

echo "[5/5] Создаю симлинк..."
if [ -L "$LINK" ] || [ -f "$LINK" ]; then
  sudo rm -f "$LINK"
fi
sudo ln -s "$TARGET" "$LINK"

echo "✅ Готово! Теперь запускайте: sysmon"
