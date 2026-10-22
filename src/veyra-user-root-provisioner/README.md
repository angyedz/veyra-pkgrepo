# Veyra user-root provisioner

This system-side package creates a persistent root filesystem and a separate
home directory for an already enrolled Veyra account. It is designed to run as
system root against the dedicated ext4 store at
`/var/lib/veyra-user-store`.

The provisioner accepts only an account name. It obtains the system UID/GID
and reserved outer mapping base from `veyra-account-registry resolve USER`,
which rechecks current enrollment eligibility. It never accepts a caller
supplied mapping, copies the host password verifier, or uses a host account's
password inside the user root.

The input root template must be a system-root-owned directory that is not
group/world writable at `/usr/share/veyra/user-root-template`. It is a trusted
system package input and must contain an executable
`/sbin/init`, a `veyrauser` account at inner UID/GID 1000, a
`/home/veyrauser` skeleton, `/usr/bin/sudo`, and a root-owned
`.veyra-user-template` marker containing `VEYRA-USER-ROOT-TEMPLATE 1`. The
provisioner rejects passwordless sudo rules and any enabled password field in
the template. It renames the inner account to the enrolled name, locks its
copied password field, creates only the six device nodes required by the
isolated runtime (`console`, `null`, `tty`, `zero`, `random`, and `urandom`),
moves home contents to the separate persistent home, then atomically publishes
both at:

```text
/var/lib/veyra-user-store/users/USER/rootfs
/var/lib/veyra-user-store/users/USER/home
```

Commands:

```text
veyra-user-root-provisioner provision USER
veyra-user-root-provisioner verify USER
```

Provisioning is idempotent: an existing root is verified and left unchanged.
An incomplete or identity-mismatched result fails closed. Root-owned metadata
outside the user-writable root records the registry identity used for
provisioning.

This package does not authenticate a login, start a session, mount user roots,
provide an inner-sudo password, configure PAM/SDDM, or enable the profile in
the installer. Inner passwords start locked; a separate reviewed credential
path is required before inner `sudo` can be enabled. The package remains
experimental until the production OpenRC manager and integrated QEMU and
independent security gates pass.
