#!/bin/bash
# Builds the Packhound virtual appliance: a minimal Debian with Packhound as
# a service, in the formats hypervisors import.
#
#   sudo appliance/build.sh <packhound-linux-amd64 binary> <version> <output dir> [ffmpeg dir]
#
# The ffmpeg dir, from scripts/build-ffmpeg.sh, gives the mosaic its decoder.
#
# Produces, in the output dir:
#   packhound-<version>.ova          VMware ESXi / Workstation / Fusion, VirtualBox
#   packhound-<version>.qcow2        Proxmox, KVM / libvirt
#   packhound-<version>.vhdx         Hyper-V (generation 1)
#
# Needs: mmdebstrap, qemu-utils, parted, e2fsprogs, grub-pc-bin, rsync. Runs as
# root because it uses a loop device.
set -euo pipefail

BIN=$(realpath "$1")
VERSION=$2
OUT=$(realpath -m "$3")
FFMPEG_DIR=${4:+$(realpath "$4")}
SUITE=${SUITE:-trixie}
MIRROR=${MIRROR:-http://deb.debian.org/debian}
SIZE=${SIZE:-8G}
HERE=$(cd "$(dirname "$0")" && pwd)

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -x "$BIN" ] || { echo "$BIN is not an executable" >&2; exit 1; }
mkdir -p "$OUT"
WORK=$(mktemp -d)
RAW=$WORK/disk.raw
MNT=$WORK/mnt
LOOP=

cleanup() {
	set +e
	for d in dev/pts dev proc sys run; do umount -l "$MNT/$d" 2>/dev/null; done
	umount -l "$MNT" 2>/dev/null
	[ -n "$LOOP" ] && losetup -d "$LOOP"
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "==> Disk"
truncate -s "$SIZE" "$RAW"
parted -s "$RAW" mklabel msdos mkpart primary ext4 1MiB 100% set 1 boot on
# The partition gets a loop device of its own, at its offset: containers and
# some CI runners have no udev to make partition devices for a loop disk.
LOOP=$(losetup -f --show -o $((2048 * 512)) "$RAW")
mkfs.ext4 -q -L packhound-root "$LOOP"
mkdir -p "$MNT"
mount "$LOOP" "$MNT"

echo "==> Debian $SUITE"
PACKAGES=(
	systemd systemd-sysv systemd-resolved systemd-timesyncd udev dbus
	linux-image-amd64 initramfs-tools grub-pc
	openssh-server sudo ca-certificates tzdata
	iproute2 iputils-ping ethtool tcpdump curl less vim-tiny nano
	cloud-guest-utils e2fsprogs
	open-vm-tools qemu-guest-agent hyperv-daemons
)
export DEBIAN_FRONTEND=noninteractive
mmdebstrap --variant=minbase --components=main \
	--include="$(IFS=,; echo "${PACKAGES[*]}")" \
	--essential-hook='echo "grub-pc grub-pc/install_devices_empty boolean true" | chroot "$1" debconf-set-selections' \
	--dpkgopt='path-exclude=/usr/share/doc/*' --dpkgopt='path-include=/usr/share/doc/*/copyright' \
	--dpkgopt='path-exclude=/usr/share/man/*' --dpkgopt='path-exclude=/usr/share/locale/*' \
	"$SUITE" "$MNT" "$MIRROR"

echo "==> Packhound"
install -m 0755 "$BIN" "$MNT/usr/local/bin/packhound"
if [ -n "$FFMPEG_DIR" ]; then
	install -D -m 0755 "$FFMPEG_DIR/ffmpeg" "$MNT/usr/lib/packhound/ffmpeg"
	install -D -m 0644 "$FFMPEG_DIR/COPYING.GPLv2" "$MNT/usr/share/doc/packhound/ffmpeg-COPYING.GPLv2"
	echo "FFmpeg 7.1.1 with x264, GPL 2 or later, built by scripts/build-ffmpeg.sh from" \
		"https://ffmpeg.org/releases/ffmpeg-7.1.1.tar.xz and https://code.videolan.org/videolan/x264" \
		> "$MNT/usr/share/doc/packhound/ffmpeg-SOURCE"
fi
cp -a "$HERE/rootfs/." "$MNT/"
echo "$VERSION" > "$MNT/etc/packhound/version"

echo "==> System"
for d in dev dev/pts proc sys run; do mount --bind "/$d" "$MNT/$d"; done
UUID=$(blkid -s UUID -o value "$LOOP")
# eth0, eth1 ... rather than names that depend on the hypervisor's PCI
# layout; the console on screen and on the first serial port.
CMDLINE="net.ifnames=0 biosdevname=0 console=ttyS0,115200n8 console=tty0"
cat > "$MNT/etc/fstab" <<EOF
UUID=$UUID / ext4 errors=remount-ro,noatime 0 1
EOF
echo packhound > "$MNT/etc/hostname"
printf '127.0.0.1\tlocalhost\n127.0.1.1\tpackhound\n::1\tlocalhost ip6-localhost ip6-loopback\n' > "$MNT/etc/hosts"
# Every deployed copy makes its own machine ID on first boot.
: > "$MNT/etc/machine-id"
rm -f "$MNT/var/lib/dbus/machine-id"
ln -sf /run/systemd/resolve/stub-resolv.conf "$MNT/etc/resolv.conf"
# Used by update-grub when a kernel upgrade regenerates grub.cfg.
cat > "$MNT/etc/default/grub" <<GRUB
GRUB_DEFAULT=0
GRUB_TIMEOUT=2
GRUB_DISTRIBUTOR="Packhound"
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
GRUB_CMDLINE_LINUX="$CMDLINE"
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --speed=115200"
GRUB
chroot "$MNT" /bin/bash -e <<'CHROOT'
passwd -l root
systemctl enable systemd-networkd systemd-resolved systemd-timesyncd
systemctl enable packhound packhound-console packhound-firstboot
systemctl mask getty@tty1.service
systemctl disable ssh 2>/dev/null || true
systemctl enable serial-getty@ttyS0.service
update-initramfs -u -k all
# GRUB's modules, and its core image for the gap before the partition.
mkdir -p /boot/grub/i386-pc
cp /usr/lib/grub/i386-pc/*.mod /usr/lib/grub/i386-pc/*.lst /boot/grub/i386-pc/
grub-mkimage -O i386-pc -p '(hd0,msdos1)/boot/grub' -o /tmp/core.img \
	biosdisk part_msdos ext2 search_fs_uuid normal configfile linux echo serial terminal
apt-get clean
rm -rf /var/lib/apt/lists/* /var/log/*.log /etc/ssh/ssh_host_*
CHROOT

# The boot loader, installed as grub-install would but without needing to
# map loop devices to disks: the boot sector's code (not the partition table
# after it), then the core image from sector 1, in the gap before the
# partition. grub-mkimage has already pointed the core's first sector at
# the rest of it.
CORE=$MNT/tmp/core.img
[ "$(stat -c %s "$CORE")" -lt $((2047 * 512)) ] || { echo "core.img does not fit before the partition" >&2; exit 1; }
dd if="$MNT/usr/lib/grub/i386-pc/boot.img" of="$RAW" bs=440 count=1 conv=notrunc status=none
dd if="$CORE" of="$RAW" bs=512 seek=1 conv=notrunc status=none
rm -f "$CORE"
# /vmlinuz and /initrd.img follow kernel upgrades; an upgrade also runs
# update-grub, which rewrites this file to the same effect.
[ -e "$MNT/vmlinuz" ] && [ -e "$MNT/initrd.img" ] || { echo "no /vmlinuz or /initrd.img in the image" >&2; exit 1; }
cat > "$MNT/boot/grub/grub.cfg" <<GRUBCFG
set timeout=2
serial --speed=115200
terminal_input console serial
terminal_output console serial
search --no-floppy --fs-uuid --set=root $UUID
menuentry 'Packhound' {
	linux /vmlinuz root=UUID=$UUID ro quiet $CMDLINE
	initrd /initrd.img
}
GRUBCFG

# A good chance of a smaller image: discard what is free.
fstrim "$MNT" 2>/dev/null || true
for d in run sys proc dev/pts dev; do umount "$MNT/$d"; done
umount "$MNT"
e2fsck -fy "$LOOP" >/dev/null || true
losetup -d "$LOOP"
LOOP=

echo "==> Images"
NAME=packhound-$VERSION
qemu-img convert -c -O qcow2 "$RAW" "$OUT/$NAME.qcow2"
qemu-img convert -O vhdx -o subformat=dynamic "$RAW" "$OUT/$NAME.vhdx"
qemu-img convert -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic "$RAW" "$WORK/$NAME-disk1.vmdk"

DISK_BYTES=$(stat -c %s "$RAW")
VMDK_BYTES=$(stat -c %s "$WORK/$NAME-disk1.vmdk")
sed -e "s/@NAME@/$NAME/g" -e "s/@VERSION@/$VERSION/g" \
    -e "s/@DISK_BYTES@/$DISK_BYTES/g" -e "s/@VMDK_BYTES@/$VMDK_BYTES/g" \
    "$HERE/packhound.ovf" > "$WORK/$NAME.ovf"
(
	cd "$WORK"
	{
		echo "SHA256($NAME.ovf)= $(sha256sum "$NAME.ovf" | cut -d' ' -f1)"
		echo "SHA256($NAME-disk1.vmdk)= $(sha256sum "$NAME-disk1.vmdk" | cut -d' ' -f1)"
	} > "$NAME.mf"
	# The OVF descriptor must come first in the archive.
	tar --format=ustar -cf "$OUT/$NAME.ova" "$NAME.ovf" "$NAME.mf" "$NAME-disk1.vmdk"
)
ls -lh "$OUT"
