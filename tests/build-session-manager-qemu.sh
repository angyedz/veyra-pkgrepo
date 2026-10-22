#!/bin/sh
set -eu

root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
out=${1:?usage: build-session-manager-qemu.sh OUTPUT_DIR}
repo=$root/packages/repo/x86_64
system=$out/system-root
store=$out/user-store

mkdir -p "$out"
[ -z "$(ls -A "$out")" ] || {
    echo "QEMU output directory must be empty: $out" >&2
    exit 1
}
for package in \
    veyra-account-registry \
    veyra-session-auth \
    veyra-user-root-provisioner \
    veyra-user-root-template \
    veyra-session-manager; do
    set -- "$repo"/"$package"-*.apk
    [ -f "$1" ] || { echo "Missing built package: $package" >&2; exit 1; }
done

kernel_version=$(find /lib/modules -mindepth 1 -maxdepth 1 -type d -print -quit)
[ -n "$kernel_version" ] || { echo 'linux-lts kernel modules are missing' >&2; exit 1; }
kernel_version=${kernel_version##*/}
[ -s /boot/vmlinuz-lts ] || { echo 'Alpine linux-lts kernel image is missing' >&2; exit 1; }

mkdir -p "$system" "$store/lost+found"
apk --root "$system" --initdb \
    --keys-dir /etc/apk/keys \
    --repositories-file /etc/apk/repositories \
    add alpine-base openrc shadow
apk --root "$system" --keys-dir /etc/apk/keys add \
    "$repo"/veyra-account-registry-*.apk \
    "$repo"/veyra-session-auth-*.apk \
    "$repo"/veyra-user-root-provisioner-*.apk \
    "$repo"/veyra-user-root-template-*.apk \
    "$repo"/veyra-session-manager-*.apk

chroot "$system" addgroup -g 23150 veyraqa
chroot "$system" adduser -D -H -u 23150 -G veyraqa \
    -s /sbin/nologin veyraqa
printf '%s:%s\n' veyraqa 'Veyra-Session-QEMU-2026!' |
    chroot "$system" chpasswd

mkdir -p "$system/var/lib/veyra-user-store" \
    "$system/etc/runlevels/default" "$system/etc/init.d"
cat > "$system/etc/fstab" <<'EOF'
/dev/vdb /var/lib/veyra-user-store ext4 defaults 0 2
EOF
cat > "$system/etc/init.d/veyra-session-qemu-enroll" <<'EOF'
#!/sbin/openrc-run
description="Enroll the disposable Veyra QEMU account"

depend() {
	need localmount
	before veyra-session-manager
}

start() {
	ebegin "Enroll disposable QEMU account"
	/usr/sbin/veyra-account-registry enroll veyraqa
	eend $?
}
EOF
chmod 0755 "$system/etc/init.d/veyra-session-qemu-enroll"
ln -s /etc/init.d/veyra-session-qemu-enroll \
    "$system/etc/runlevels/default/veyra-session-qemu-enroll"
ln -s /etc/init.d/veyra-session-manager \
    "$system/etc/runlevels/default/veyra-session-manager"
cat > "$system/etc/inittab" <<'EOF'
::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default
::shutdown:/sbin/openrc shutdown
ttyS0::respawn:/usr/sbin/veyra-login
EOF

truncate -s 768M "$out/system.raw"
truncate -s 768M "$out/user-store.raw"
mkfs.ext4 -F -q -L VEYRA_QEMU_SYSTEM \
    -E root_owner=0:0 -d "$system" "$out/system.raw"
mkfs.ext4 -F -q -L VEYRA_QEMU_USER_STORE \
    -E root_owner=0:0 -d "$store" "$out/user-store.raw"
mkinitfs -F 'base ext4 virtio' -o "$out/initramfs" "$kernel_version"
cp /boot/vmlinuz-lts "$out/kernel"
chmod 0644 "$out/kernel" "$out/initramfs" \
    "$out/system.raw" "$out/user-store.raw"

test -s "$system/etc/pam.d/veyra-login"
test -x "$system/usr/sbin/veyra-session-manager"
test -x "$system/usr/sbin/veyra-user-root-provisioner"
test -d "$system/usr/share/veyra/user-root-template"
echo "Built disposable PAM session guest with Alpine kernel $kernel_version"
