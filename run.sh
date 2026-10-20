#!/bin/sh
# Lumen OS 2 — build (if needed), create the data disk, start the YouTube bridge, boot QEMU.
set -e
cd "$(dirname "$0")"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
mkdir -p build

# 1. build if needed
if [ ! -f build/Image ] || [ ! -f build/initramfs.cpio ] || \
   [ -n "$(find src kernel docker third_party -type f -newer build/initramfs.cpio | head -1)" ]; then
  ./build.sh
fi

# 2. data disk (raw, holds notes/settings/history; see src/store.c)
DATA="${LUMEN_DATA:-data.img}"
[ -f "$DATA" ] || { echo "Creating $DATA"; dd if=/dev/zero of="$DATA" bs=1048576 count=8 2>/dev/null; }

# 3. storage disk for /data (Terminal home, installed APKs, downloads): raw ext4 image, created once.
#    Formatted inside the toolchain container because macOS has no mkfs.ext4. If this step fails the
#    phone still boots and /data lives in RAM.
STORE="${LUMEN_STORAGE:-storage.img}"
if [ ! -f "$STORE" ]; then
  echo "Creating $STORE (4 GB sparse, ext4)"
  dd if=/dev/zero of="$STORE" bs=1048576 count=0 seek=4096 2>/dev/null
  docker run --rm -v "$PWD":/w lumen-toolchain sh -c "command -v mke2fs >/dev/null || apk add -q e2fsprogs >/dev/null; mke2fs -q -t ext4 -F /w/$STORE" \
    || echo "(could not format $STORE; /data will be RAM-only. Delete $STORE and re-run once docker works.)"
fi
mkdir -p apks

# 3b. YouTube bridge (stopped again when QEMU exits)
BRIDGE=""
if [ -z "$LUMEN_NO_BRIDGE" ]; then
  python3 bridge/ytbridge.py > build/bridge.log 2>&1 &
  BRIDGE=$!
fi
cleanup() { [ -n "$BRIDGE" ] && kill "$BRIDGE" 2>/dev/null; rm -f build/qmp.sock; }
trap cleanup EXIT INT TERM

# 4. QEMU (QMP socket at build/qmp.sock for tests)
AUDIO="${LUMEN_AUDIO:-coreaudio,id=snd0}"
rm -f build/qmp.sock
echo "Connect VNC to localhost:5901"
qemu-system-aarch64 -M virt -accel hvf -cpu host -smp 4 -m 2048 \
  -kernel build/Image -initrd build/initramfs.cpio \
  -append "console=ttyAMA0 loglevel=4" \
  -device virtio-gpu-pci,xres=720,yres=1560 \
  -device virtio-tablet-pci -device virtio-keyboard-pci \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -audiodev "$AUDIO" -device virtio-sound-pci,audiodev=snd0 \
  -drive file="$DATA",format=raw,if=none,id=d0 -device virtio-blk-pci,drive=d0 \
  -drive file="$STORE",format=raw,if=none,id=d1 -device virtio-blk-pci,drive=d1 \
  -device virtio-rng-pci \
  -rtc base=localtime \
  -vnc localhost:1 -display none \
  -serial file:build/serial.log \
  -qmp unix:build/qmp.sock,server,nowait
