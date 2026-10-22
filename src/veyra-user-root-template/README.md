# Veyra isolated user-root template

This package installs a pinned Alpine 3.22.7 x86_64 minirootfs below
`/usr/share/veyra/user-root-template` and adds `sudo` from Alpine's signed 3.22
repositories. The inner root keeps the Alpine package database, keys, and
repositories so user environments can manage their own packages independently.

The template includes `/sbin/init`, BusyBox `ash`, a `veyrauser` account at
UID/GID 1000, and a separate home skeleton. All template password fields are
locked. Its `sudo` binary is not setuid in the package; the system-side
provisioner enables it only after assigning mapped ownership to an individual
root. The default sudo policy grants no privilege to `veyrauser`; the
provisioner also rejects active passwordless sudo rules. No host account
password verifier is copied into an isolated root.

The minirootfs archive is pinned by SHA-512. To update the Alpine base, update
`pkgver`, the matching v3.22 source URL, and `sha512sums` together, then verify
the rebuilt root with `veyra-user-root-provisioner verify` before enabling
sessions.

This package is an x86_64 prototype. It does not provide a desktop, configure
the session service, or grant inner root access. The user-root provisioner
depends on this package so the login manager cannot be installed with a missing
template.
