# V-Dri capability map and implementation plan

## Goal

`v-dri` will report detected PCI devices, the driver currently bound to each
device, candidate in-tree modules, kernel compatibility, module-signature
policy, and useful driver-related boot diagnostics. Future mutations may only
activate driver artifacts that are compatible with the exact Veyra kernel and
deployment and that satisfy the system's trust policy.

## Capability map

| Capability | Responsibility | Depends on |
|---|---|---|
| `inventory` | Read PCI/DRM devices and current bindings | Linux sysfs |
| `compatibility` | Match kernel aliases and check module vermagic/signature state | kmod, running kernel |
| `diagnostics` | Explain missing bindings, unavailable modules, and policy blockers | inventory, compatibility |
| `catalog` | Find approved driver packages and compatible artifacts | signed Veyra/Fedora metadata |
| `activation` | Stage/reboot/rollback compatible driver changes | OTA, vpkg, signed artifact policy |

Build order: inventory → compatibility → diagnostics → catalog → activation.

## First deliverable: read-only inventory and diagnosis

This package inventories all detected PCI devices and implements
`inventory`, `compatibility`, and local
`diagnostics`. It must never install packages, write kernel/module state, run
`modprobe`, load/unload a module, change boot settings, or disable Secure Boot.
Candidate matching uses `modprobe --resolve-alias` only; module metadata comes
from `modinfo`. Missing host tools are reported as unavailable evidence, not
interpreted as proof that a device is unsupported.

The JSON output is versioned and stable enough for a future GUI or support
bundle. Text output is intended for a person troubleshooting a device.
`doctor` reads at most the latest 2,000 kernel-journal lines from the current
boot and returns at most 40 filtered findings. It does not save or upload logs;
the journal may be unavailable to an unprivileged user.

## Trust and activation boundary

`v-dri` must not replace the official kernel; kernel changes go through OTA.
Driver packages come from Fedora's official repositories. The first-party Veyra
RPM repository contains Veyra software such as `v-dri`, `vpkg`, `vforge`, and
`veyra-update`; it does not carry kernel or driver modules. No RPM Fusion or
other third-party driver repositories are enabled by this component.

The current Veyra UKIs are unsigned. `v-dri` therefore does not install,
activate, or load external modules and does not enroll keys, relax module
signature enforcement, disable Secure Boot, or make unsigned modules loadable.
Any future support for out-of-tree modules requires a separately approved
signing, provenance, OTA-binding, and rollback design.

## Commands

- `v-dri status [--json]`: inventory detected PCI devices and
  report their bound driver and available alias-matched module candidates.
- `v-dri doctor [--json]`: the same inventory with actionable policy and
  compatibility findings plus recent driver-related kernel log errors; exits
  1 if a detected device has a driver issue.
- `v-dri --help`: show supported commands.

There is intentionally no `install`, `enable`, `disable`, or `load` command in
this implementation.

## Verification

- Unit tests use a synthetic sysfs tree and stubbed read-only `modprobe` and
  `modinfo` queries.
- Fedora 44 GitHub Actions builds the RPM, installs it in a disposable Fedora
  44 container, and checks CLI/JSON behavior.
- Runtime device support, Veyra OTA binding, external module signatures,
  rollback, and physical GPU behavior remain unproven until a dedicated QEMU
  guest test (and appropriate virtual-device model) exists.

## Follow-up tasks

- [ ] Resolve only Fedora-official driver/provider packages, using libdnf5 or
  vpkg APIs and never adding host DNF CLI.
- [ ] Define supported Fedora package flows for graphics, network and other
  driver updates; all kernel/module changes remain OTA-owned.
- [ ] Integrate supported driver updates with OTA candidate preparation and
  safe rollback.
- [ ] Exercise compatible and incompatible packages, module signature
  enforcement, kernel upgrades, OTA fallback, and diagnostics in QEMU.
- [ ] Treat out-of-tree driver modules as out of scope unless the project later
  approves a separate signed-artifact and key-enrollment design.
