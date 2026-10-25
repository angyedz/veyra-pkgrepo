# V-Dri command scope

The initial `v-dri` command is read-only. It inventories PCI devices, reports
bound drivers and alias-matched module candidates,
compares module vermagic with the running kernel, and reports whether module
signature enforcement can be determined.

It does not install packages, load or unload modules, change boot settings,
enroll keys, or weaken Secure Boot. Kernel and in-tree module changes remain
owned by Veyra OTA; this command only reports device and module state. See the
source repository's `docs/v-dri-architecture.md` for the full capability map
and remaining work.

`v-dri doctor` reads at most the last 2,000 kernel-journal lines from the
current boot and prints up to 40 filtered driver findings. It never saves or
uploads logs; the journal can be unavailable to unprivileged users.
