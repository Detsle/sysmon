#!/usr/bin/env bash
set -euo pipefail

TARGET="$HOME/sysmon.py"
ALIAS_LINE='alias sysmon="python3 ~/sysmon.py"'

echo "[1/5] Определение ОС..."
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS=$ID
else
  OS="unknown"
fi
echo "Обнаружена ОС: $OS"

echo "[2/5] Установка Python3 и pip..."
case "$OS" in
  ubuntu|debian)
    sudo apt update
    sudo apt install -y python3 python3-pip
    ;;
  centos|rhel|fedora)
    sudo yum install -y python3 python3-pip || sudo dnf install -y python3 python3-pip
    ;;
  arch)
    sudo pacman -Sy --noconfirm python python-pip
    ;;
  *)
    echo "⚠️ Неизвестная ОС, убедитесь что python3 и pip установлены вручную."
    ;;
esac

echo "[3/5] Установка psutil..."
python3 -m pip install --user psutil

echo "[4/5] Копирую sysmon.py..."
cp ./sysmon.py "$TARGET"
chmod 644 "$TARGET"

echo "[5/5] Добавляю alias..."
touch "$HOME/.bashrc"
if ! grep -Fxq "$ALIAS_LINE" "$HOME/.bashrc"; then
  echo "$ALIAS_LINE" >> "$HOME/.bashrc"
  echo "Alias добавлен."
fi
source "$HOME/.bashrc"

echo "✅ Готово! Запускайте: sysmon"
