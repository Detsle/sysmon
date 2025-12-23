#!/usr/bin/env bash
set -euo pipefail

TARGET="$HOME/sysmon.py"
ALIAS_LINE='alias sysmon="python3 ~/sysmon.py"'

echo "[1/4] Проверка Python3..."
if ! command -v python3 >/dev/null 2>&1; then
  echo "Устанавливаю python3..."
  sudo apt update && sudo apt install -y python3
fi

echo "[2/4] Установка psutil..."
python3 -m pip install --user psutil >/dev/null 2>&1 || python3 -m pip install --user psutil

echo "[3/4] Копирую sysmon.py..."
cp ./sysmon.py "$TARGET"
chmod 644 "$TARGET"

echo "[4/4] Добавляю alias..."
touch "$HOME/.bashrc"
if grep -Fxq "$ALIAS_LINE" "$HOME/.bashrc"; then
  echo "Alias уже существует."
else
  echo "$ALIAS_LINE" >> "$HOME/.bashrc"
  echo "Alias добавлен."
fi

# shellcheck disable=SC1090
source "$HOME/.bashrc"

echo "✅ Готово! Запускайте: sysmon"
