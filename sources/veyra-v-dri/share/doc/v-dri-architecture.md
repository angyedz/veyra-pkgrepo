# V-Dri command scope

The initial `v-dri` command is read-only. It inventories PCI devices, reports
bound drivers and alias-matched module candidates,
compares module vermagic with the running kernel, and reports whether module
signature enforcement can be determined.

It does not install packages, load or unload modules, change boot settings,
enroll keys, or weaken Secure Boot. Driver activation is withheld until Veyra
has an approved signed-artifact, key-enrollment, OTA-binding, and rollback
design. See the source repository's `docs/v-dri-architecture.md` for the full
capability map and remaining work.
