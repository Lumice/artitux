#!/usr/bin/env bash
set -euo pipefail

KO="${1:-$(cd "$(dirname "$0")/.." && pwd)/artitux_kmod.ko}"
KREL="${KREL:-$(uname -r)}"
KERNEL="${KERNEL:-/boot/vmlinuz-${KREL}}"
TEST_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -r "$KO" ]; then
    echo "Module not found: $KO" >&2
    exit 1
fi
if [ ! -r "$KERNEL" ]; then
    echo "Kernel image not readable: $KERNEL" >&2
    exit 1
fi
if ! command -v qemu-system-x86_64 >/dev/null 2>&1 || [ ! -w /dev/kvm ]; then
    echo "QEMU or /dev/kvm unavailable" >&2
    exit 1
fi

TMP="$(mktemp -d /tmp/artitux-kmod-vm.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/root"
gcc -static -O2 -Wall -Wextra -pthread "$TEST_DIR/vm_test.c" -o "$TMP/root/init"
cp "$KO" "$TMP/root/artitux_kmod.ko"
chmod +x "$TMP/root/init"

(cd "$TMP/root" && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -1 > "$TMP/initramfs.cpio.gz")

echo "Booting $KERNEL in QEMU/KVM (-cpu host -smp 4, IBT/FRED default)..."
timeout -k 5 45s qemu-system-x86_64 \
    -enable-kvm \
    -cpu host \
    -smp 4 \
    -m 512M \
    -display none \
    -monitor none \
    -serial "file:$TMP/serial.log" \
    -no-reboot \
    -kernel "$KERNEL" \
    -initrd "$TMP/initramfs.cpio.gz" \
    -append "console=ttyS0,115200 rdinit=/init panic=1 quiet loglevel=4" </dev/null

cat "$TMP/serial.log"
grep -q "VM TEST RESULT: ALL PASSED" "$TMP/serial.log"
