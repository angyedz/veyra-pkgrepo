# Veyra account registry

This package provides the first production-oriented Stage 1 primitive for
dual-environment accounts: a system-root-only registry that assigns each
eligible system account a unique, non-reused 65,536-ID mapping range.

The registry is stored at
`/var/lib/veyra-user-store/registry/accounts.v1`. The account store must be a
dedicated ext4 mount at `/var/lib/veyra-user-store`, separate from `/var/lib`'s
system filesystem. The registry directory and file are root-owned with modes
`0700` and `0600`. Updates are locked, written to a new file, synced, atomically
renamed, and followed by a directory sync. Retiring an account preserves its
record and ID-range reservation; it does not remove user data.

Commands:

```text
veyra-account-registry enroll USER
veyra-account-registry retire USER
veyra-account-registry resolve USER
veyra-account-registry list
```

Enrollment accepts only an existing normal system account with an active,
unexpired system-authenticator password and a locked non-shell system login
path. It rejects host `wheel` or `sudo` membership and, when host `sudo` is
installed, asks its policy engine to confirm that the account has no host sudo
authorization. An unavailable, invalid, or slow policy check fails closed.
Password verifiers are checked through the system shadow database but are
never copied to the registry or user root. Mappings start at outer UID/GID
base 300000 and advance in non-overlapping 100000-ID slots. Failed allocation
never reuses an earlier slot.

`resolve USER` is the manager-facing lookup for an enrolled account. On every
call it rechecks the current password state, shell, expiry, host privilege
groups and sudo policy, and confirms that the system UID/GID still match the
enrolled values. It emits one tab-separated record containing the account
name, system UID, system GID and reserved mapped-ID base. It never emits
password data. A missing, retired, changed or newly privileged account fails
closed.

This package only manages identity-to-range reservations. It does not create
or mount user roots, start sessions, provide a login broker, or enable the
Dual Environment profile. It is not yet included in `veyra-meta` or the normal
installer. Do not enable the profile until root provisioning, the OpenRC
session manager, authenticated TTY login, graphical session routing, storage
recovery, and the integrated QEMU and independent security gates pass.
