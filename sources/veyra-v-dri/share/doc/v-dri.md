# v-dri driver diagnostics

`v-dri status` is the first read-only slice of Veyra's driver manager. It
enumerates DRM cards from sysfs, reports PCI vendor/device IDs when available,
the bound kernel driver/module, module taint flags, and whether the running
kernel enforces signatures for loadable modules. `v-dri status --json` prints
schema-2 JSON for diagnostics and future integration.

The image passes `module.sig_enforce=1` to Fedora's kernel. `v-dri` reports
`module_signature_enforcement` as `enforced`, `permissive`, or `unavailable`;
only `enforced` is considered healthy. The kernel accepts modules signed by a
key it trusts. This does not prove that every accepted module was signed by
Fedora, and the current prototype does not add a Veyra key, support MOK
enrollment, download, install, sign, or activate modules. Fedora's in-tree
drivers remain the supported driver source. If Linux marks a loaded module
with the `O` (out-of-tree) taint flag, v-dri reports
`external-module-detected` and exits with status 2.

Exit codes:

- `0`: at least one DRM card is bound to a driver without an out-of-tree taint, and module signature enforcement is active.
- `1`: sysfs or driver metadata could not be read safely.
- `2`: no DRM cards, an unbound card, an out-of-tree module, or missing module-signature enforcement was found.

Unit tests use synthetic sysfs fixtures. The Fedora 44 GitHub Actions check
also boots the image in QEMU with a virtual GPU and requires signature
enforcement plus a bound `virtio_gpu` driver. These checks do not establish real
AMD/NVIDIA compatibility or implement driver installation/activation.
