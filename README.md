# Veyra Package Repository

Official distribution repository for Veyra-specific Alpine APK packages.

## Scope

Packages here complement Alpine Stable and nixpkgs. glenv is a glibc compatibility layer, **not** a package manager; no per-application glenv wrappers are required.

## Repository layout

```
stable/v1/x86_64/     # Veyra 1.x packages and APKINDEX.tar.gz
testing/v1/x86_64/    # Test packages
keys/                  # Public APK signing keys only
```

**Never commit a private signing key.** APK files and APKINDEX must be signed with a persistent trusted key. The public key is installed on Veyra machines in `/etc/apk/keys` before enabling this repository.

## Publishing policy

1. Build and test packages in the source repository (`angyedz/Veyra-Linux`).
2. Sign packages and their index with the stable Veyra abuild key.
3. Stage a complete repository snapshot, then publish it to this repository.
4. Promote tested packages to `stable`; use `testing` for prereleases.
5. Clients keep Alpine `v3.xx/main` and `community` pinned within their Veyra major version; major Alpine upgrades require an explicit `vpkg system-upgrade`.

The signed `vpkg` and `veyra-glenv` APKs and their signed index are published under `stable/v1/x86_64/`. Veyra's `scripts/setup-pkgrepo.sh` embeds the pinned public key and configures this repository. End-to-end APK installation on a clean Alpine VM is still pending validation; do not bypass signature checks.

## Hosting caveat

GitHub's raw repository paths are not a guaranteed production APK mirror; GitHub availability in Russia and sustained binary distribution must be tested. The package layout is portable to a normal HTTPS mirror later.
