# Veyra Linux package repository

This repository contains **only packages maintained specifically for Veyra Linux**. It is not a Fedora mirror and does not rebuild Fedora's system packages. Fedora repositories provide the base system, drivers, libraries, and dependency providers. `vpkg` will resolve these together with Veyra add-on packages through DNF/libdnf5.

The Git repository has one code branch: `main`. Inside the RPM repository there are two **package channels**, also called package branches:

- `testing` contains packages awaiting validation.
- `main` is the promoted, stable package channel. The first Veyra release is still Veyra Linux pre-alpha; this channel name does not claim that Veyra Linux 1.0 has shipped.

These package channels are directories, not Git branches:

- `repo/testing/x86_64/`
- `repo/main/x86_64/`

The repository currently includes a small `veyra-release` RPM to exercise spec parsing, RPM signing, repository metadata generation, and DNF installation end to end. New Veyra components such as `veyra-updater` and `veyra-welcome` belong here when their Fedora-native implementations are ready. This repository will not carry the complete Fedora system package set.

## Production download contract: GitHub Releases only

Do not point Veyra Next `vpkg` at `raw.githubusercontent.com`, GitHub
Pages, or the generated `repo/` Git tree. Those historical directories
are not a Veyra Next package distribution channel.

The signed snapshot is a pair of GitHub Release assets:

- Stable: `rpm-vX.Y.Z` (non-prerelease); testing: `rpm-vX.Y.Z-testing`.
- `veyra-rpm-repo-x86_64.tar.gz`: contains `x86_64/`, signed
  `repodata/repomd.xml.asc`, and individually signed sysext-wrapper RPMs.
- `veyra-rpm-repo-x86_64.tar.gz.sha256`: checks the transported bytes.
  The archive is limited to 512 MiB to satisfy the current vpkg client
  (and is well below GitHub's 2 GB per-asset limit).

The client selects the highest valid versioned Release for the channel,
downloads over HTTPS, verifies archive integrity and the repository metadata
signature against **the public RPM key pinned in the installed system image**.
A checksum stored beside an archive is not itself a trusted signature.

To publish: provision `VEYRA_RPM_GPG_PRIVATE_KEY_B64` and run the
**Publish Veyra RPM repository** workflow from `main` with channel
`testing` and version `X.Y.Z`. After validation, select channel
`main` with the **same** version; stable copies and re-verifies the
existing testing release archive rather than rebuilding different content.
The workflow refuses to overwrite an existing release and downloads published
assets again to verify their bytes and signature. Ordinary source pushes
build test artifacts only and **never** publish RPM channel content.

The installed Veyra Next image must embed the exact corresponding public key.
Until the signing key is provisioned on both repositories and the signed
image/release pipeline is validated, package updates from Veyra's own Releases
remain unavailable. The CI-only temporary key is deliberately untrusted by
installed clients.

## Build and signing

Package recipes live in `rpms/<package>/`. Build locally in a Fedora environment with `rpm-build`, `rpm-sign`, `createrepo_c`, and `gnupg2` installed, and a signing key available in `GNUPGHOME`:

```sh
export VEYRA_RPM_GPG_FINGERPRINT=YOUR_SIGNING_KEY_FINGERPRINT
bash scripts/build-rpm-repo.sh /tmp/veyra-repo/x86_64
```

Pull request checks use disposable keys and validate the RPM plus signed repository metadata without publishing. A push to `main` runs package checks and creates an ephemeral CI artifact, not a public release. Stable and testing GitHub Releases are created only by authenticated manual workflow dispatch using the dedicated signing key.

Publishing expects an armored OpenPGP private key, base64-encoded as the GitHub Actions secret `VEYRA_RPM_GPG_PRIVATE_KEY_B64`. The workflow's built-in `GITHUB_TOKEN` only commits generated repository snapshots; it is not a package-signing key. The legacy `VEYRA_ABUILD_PRIVATE_KEY_B64` signs APKs and is not an RPM/OpenPGP key. A GitHub Personal Access Token also cannot sign RPM package payloads. Never place private signing material in the repository.

If the RPM-specific secret is absent, the automatic testing build creates a temporary signed CI artifact and skips channel publication. Stable promotion requires the RPM-specific key and an already-published testing snapshot.
