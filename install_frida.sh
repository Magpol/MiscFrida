#!/usr/bin/env bash
# https://github.com/Magpol/MiscFrida/install_frida.sh
set -euo pipefail

if ! command -v adb >/dev/null 2>&1; then echo "adb not found"; exit 1; fi
if ! command -v curl >/dev/null 2>&1; then echo "curl not found"; exit 1; fi

if command -v jq >/dev/null 2>&1; then
  use_jq=1
else
  use_jq=0
fi

if ! command -v xz >/dev/null 2>&1 && ! command -v unxz >/dev/null 2>&1; then
  echo "xz/unxz not found"; exit 1
fi

if ! adb get-state >/dev/null 2>&1; then
  echo "No device detected via adb"; exit 1
fi

is_root=""
uid=$(adb shell id -u 2>/dev/null | tr -d '\r' | tr -d '\n')
if [ "$uid" = "0" ]; then
  is_root="adbd"
else
  uid=$(adb shell su -c id -u 2>/dev/null | tr -d '\r' | tr -d '\n' || true)
  if [ "$uid" = "0" ]; then
    is_root="su"
  fi
fi

if [ -z "$is_root" ]; then
  echo "Device is not rooted or su not accessible"; exit 1
fi

abi=$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r' | tr -d '\n')
case "$abi" in
  arm64-v8a*) arch="arm64" ;;
  armeabi-v7a*|armeabi*) arch="arm" ;;
  x86_64*) arch="x86_64" ;;
  x86*) arch="x86" ;;
  *) echo "Unsupported ABI: $abi"; exit 1 ;;
esac

if [ "$use_jq" -eq 1 ]; then
  tag=$(curl -fsSL https://api.github.com/repos/frida/frida/releases/latest | jq -r .tag_name)
else
  tag=$(curl -fsSL https://github.com/frida/frida/releases | grep -Eo 'Frida [0-9]+\.[0-9]+\.[0-9]+' | head -n1 | awk '{print $2}')
fi

if [ -z "$tag" ] || [ "$tag" = "null" ]; then
  echo "Could not determine latest Frida release"; exit 1
fi

bin_local="frida-server-${tag}-android-${arch}"
archive="${bin_local}.xz"
remote_path="/data/local/tmp/frida-server"

if [ ! -f "$bin_local" ]; then
  if [ ! -f "$archive" ]; then
    echo "Downloading ${archive}"
    curl -fL -o "$archive" "https://github.com/frida/frida/releases/download/${tag}/${archive}"
  fi
  if command -v unxz >/dev/null 2>&1; then
    unxz -f "$archive"
  else
    xz -d -f "$archive"
  fi
fi

adb push "$bin_local" "$remote_path" >/dev/null
adb shell "chmod 755 $remote_path"

if [ "$is_root" = "adbd" ]; then
  adb shell "$remote_path >/dev/null 2>&1 &"
else
  adb shell "su -c '$remote_path >/dev/null 2>&1 &'"
fi

echo "frida-server ${tag} started on device (arch=${arch}, root=${is_root})"
