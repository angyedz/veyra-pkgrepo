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

## Trust and activation boundary

`v-dri` must not replace the official kernel; kernel changes go through OTA.
External modules must be built for and tied to the exact kernel release and
deployment identity, carry an accepted signature, and have their artifact
digest verified before staging. The tool must not enroll keys, relax module
signature enforcement, disable Secure Boot, or make unsigned modules loadable.

The current Veyra UKIs are unsigned and there is no approved Veyra module-key
enrollment or signed driver-artifact pipeline. Therefore this package does not
offer driver installation or activation. Before that capability is added, the
project must approve the signing-key ownership, enrollment and recovery model,
whether upstream/Fedora-signed modules are accepted, artifact provenance,
OTA binding, and rollback behavior. This is an explicit architectural gate,
not an automatic consent prompt.

## Commands

- `v-dri status [--json]`: inventory detected PCI devices and
  report their bound driver and available alias-matched module candidates.
- `v-dri doctor [--json]`: the same inventory with actionable policy and
  compatibility findings; exits 1 if a detected device has a driver issue.
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

- [ ] Define and approve the module-signing and key-enrollment model.
- [ ] Define signed, versioned driver artifact metadata bound to kernel NEVRA,
  kernel release, deployment root hash, and image version.
- [ ] Add repository/catalog resolution without adding host DNF CLI.
- [ ] Integrate candidate activation with OTA and safe rollback.
- [ ] Exercise compatible and incompatible modules, signature rejection,
  kernel upgrade, OTA fallback, and diagnostics inside QEMU.
