#!/usr/bin/env bash
set -euo pipefail

TARGET="$HOME/sysmon.py"
ALIAS_LINE='alias sysmon="python3 ~/sysmon.py"'

echo "[1/6] Определение ОС..."
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS=$ID
else
  OS="unknown"
fi
echo "Обнаружена ОС: $OS"

echo "[2/6] Установка Python3 и pip..."
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

echo "[3/6] Установка psutil..."
if command -v apt >/dev/null 2>&1; then
  if sudo apt install -y python3-psutil; then
    echo "psutil установлен через apt."
  else
    echo "apt не смог поставить psutil, пробую pip..."
    python3 -m pip install --user psutil --break-system-packages
  fi
else
  echo "apt недоступен, пробую pip..."
  python3 -m pip install --user psutil --break-system-packages
fi

echo "[4/6] Копирую sysmon.py..."
cp ./sysmon.py "$TARGET"
chmod 644 "$TARGET"

echo "[5/6] Добавляю alias..."
touch "$HOME/.bashrc"
if ! grep -Fxq "$ALIAS_LINE" "$HOME/.bashrc"; then
  echo "$ALIAS_LINE" >> "$HOME/.bashrc"
  echo "Alias добавлен."
fi

echo "[6/6] Активирую alias..."
# shellcheck disable=SC1090
source "$HOME/.bashrc"

echo "✅ Готово! Запускайте: sysmon"
