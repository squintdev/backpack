#!/bin/bash
# Build a bootable Arch Linux ARM SD card that boots straight into backpack.
#
#   sudo ./build-sd.sh /dev/sdX [rpi-aarch64]
#
# DESTROYS everything on the target device. Run on any Linux host with:
#   bsdtar, curl, parted, mkfs.vfat, mkfs.ext4
#
# Arch Linux ARM has no archiso equivalent; the supported path is exactly
# this: partition, extract their rootfs tarball, customize. After first boot
# on the Pi, log in (alarm/alarm default is replaced below with autologin)
# and run /root/install-backpack.sh.
set -euo pipefail

DEV="${1:?usage: build-sd.sh /dev/sdX [rpi-aarch64]}"
FLAVOR="${2:-rpi-aarch64}"
TARBALL="ArchLinuxARM-${FLAVOR}-latest.tar.gz"
URL="http://os.archlinuxarm.org/os/${TARBALL}"

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -b "$DEV" ] || { echo "$DEV is not a block device"; exit 1; }

echo "This ERASES ${DEV}:"
lsblk "$DEV"
read -rp "type the device path again to confirm: " confirm
[ "$confirm" = "$DEV" ] || { echo "aborted"; exit 1; }

# --- partition: 256M FAT boot + rest ext4 root ------------------------------
parted -s "$DEV" mklabel msdos \
    mkpart primary fat32 1MiB 257MiB \
    mkpart primary ext4 257MiB 100%
# partition name suffix differs between /dev/sdX and /dev/mmcblkX
case "$DEV" in
    *[0-9]) P="p" ;;
    *) P="" ;;
esac
BOOT="${DEV}${P}1"
ROOT="${DEV}${P}2"
mkfs.vfat -F32 "$BOOT"
mkfs.ext4 -qF "$ROOT"

# --- extract rootfs ---------------------------------------------------------
MNT=$(mktemp -d)
mount "$ROOT" "$MNT"
mkdir -p "$MNT/boot"
mount "$BOOT" "$MNT/boot"

if [ ! -f "$TARBALL" ]; then
    echo "downloading ${URL}…"
    curl -fLO "$URL"
fi
echo "extracting rootfs…"
bsdtar -xpf "$TARBALL" -C "$MNT"

# --- deck customization -----------------------------------------------------
# Autologin on tty1…
mkdir -p "$MNT/etc/systemd/system/getty@tty1.service.d"
cat > "$MNT/etc/systemd/system/getty@tty1.service.d/autologin.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin alarm --noclear %I $TERM
EOF

# …then boot straight into the launcher; quitting it logs out and getty
# restarts it. `!` inside backpack still gives a real shell.
cat >> "$MNT/home/alarm/.bash_profile" <<'EOF'
if [ "$(tty)" = "/dev/tty1" ] && command -v backpack >/dev/null; then
    exec backpack
fi
EOF

# Install script available on first boot.
install -Dm755 "$(dirname "$0")/install-backpack.sh" \
    "$MNT/home/alarm/install-backpack.sh"

sync
umount "$MNT/boot" "$MNT"
rmdir "$MNT"

echo
echo "done. First boot on the Pi:"
echo "  1. it lands in a shell (backpack not installed yet)"
echo "  2. get network up, then: sudo ./install-backpack.sh"
echo "  3. reboot — the deck now boots into backpack"
echo "USB identity: backpack --keyring /path/to/usb/keyring.veil"
