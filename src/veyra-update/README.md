# Veyra system updater

`veyra-update --check` lists available APK upgrades on a conventional
single-root installation. `sudo veyra-update` applies them there.

An installation marked `atomic-v1` must never upgrade the active system root
in place. In that mode, the command delegates to the root-owned
`/usr/sbin/veyra-atomic-update` helper included in this package. The package
also installs the paired-root staging, initramfs and boot-selection helpers
used by that transaction. Unknown or unsafe deployment-mode metadata fails
closed.

The helper verifies a signed x86_64 paired-release manifest, stages system
and user APK worlds into inactive roots, and arms a trial only after both
roots verify. Applying currently requires the independent Veyra Recovery
Environment; it deliberately refuses to modify a running installation.

This package does not provision a release channel or trust key. Before
`--check` can contact a channel, the system image must install a root-owned
HTTPS manifest URL at `/etc/veyra/update-manifest-url` and the matching
root-owned Ed25519 public key at `/etc/veyra/trust/update-ed25519.pub`. The
Recovery Environment must carry the same trusted key and the updater/runtime
dependencies before it can apply releases. Until that integration and an
end-to-end QEMU update/rollback test pass, this is an experimental component,
not a usable OTA update service.

The path checks in the `veyra-update` frontend are an accidental-misuse
guard, not a privilege boundary; system package and update policy remains
owned by the protected system environment.
