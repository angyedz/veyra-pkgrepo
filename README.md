# Veyra Linux package repository

This repository contains **only packages maintained specifically for Veyra Linux**. It is not a Fedora mirror and does not rebuild Fedora's system packages. Fedora repositories provide the base system, drivers, libraries, and dependency providers. `vpkg` will resolve these together with Veyra add-on packages through DNF/libdnf5.

The Git repository has one code branch: `main`. Inside the RPM repository there are two **package channels**, also called package branches:

- `testing` contains packages awaiting validation.
- `main` is the promoted, stable package channel. The first Veyra release is still Veyra Linux pre-alpha; this channel name does not claim that Veyra Linux 1.0 has shipped.

These package channels are directories, not Git branches:

- `repo/testing/x86_64/`
- `repo/main/x86_64/`

The repository currently includes a small `veyra-release` RPM to exercise spec parsing, RPM signing, repository metadata generation, and DNF installation end to end. New Veyra components such as `veyra-updater` and `veyra-welcome` belong here when their Fedora-native implementations are ready. This repository will not carry the complete Fedora system package set.

## Configure a package channel

The testing channel:

```ini
[veyra-testing]
name=Veyra Linux testing packages
baseurl=https://raw.githubusercontent.com/angyedz/veyra-pkgrepo/main/repo/testing/x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://raw.githubusercontent.com/angyedz/veyra-pkgrepo/main/repo/testing/x86_64/RPM-GPG-KEY-VEYRA
```

For the stable package channel, use repository ID `veyra-main` and replace `repo/testing` with `repo/main`. The raw GitHub URL is a development mirror; a production release needs a separately validated CDN or package host. The public signing key must be pinned by the Veyra image or another trusted bootstrap before enabling the repository. Fetching a key from the same repository it authenticates is not a trust bootstrap.

## Build and signing

Package recipes live in `rpms/<package>/`. Build locally in a Fedora environment with `rpm-build`, `rpm-sign`, `createrepo_c`, and `gnupg2` installed, and a signing key available in `GNUPGHOME`:

```sh
export VEYRA_RPM_GPG_FINGERPRINT=YOUR_SIGNING_KEY_FINGERPRINT
bash scripts/build-rpm-repo.sh /tmp/veyra-repo/x86_64
```

Pull request checks use disposable keys and validate the RPM plus signed repository metadata without publishing. A push to GitHub's `main` code branch builds and publishes the signed `testing` package channel. After validating that snapshot, dispatch **Publish Veyra RPM repository** from Git branch `main` with package channel `main` to promote the exact RPM files into the stable package channel.

Publishing expects an armored OpenPGP private key, base64-encoded as the GitHub Actions secret `VEYRA_RPM_GPG_PRIVATE_KEY_B64`. The workflow's built-in `GITHUB_TOKEN` only commits generated repository snapshots; it is not a package-signing key. The legacy `VEYRA_ABUILD_PRIVATE_KEY_B64` signs APKs and is not an RPM/OpenPGP key. A GitHub Personal Access Token also cannot sign RPM package payloads. Never place private signing material in the repository.

If the RPM-specific secret is absent, the automatic testing build creates a temporary signed CI artifact and skips channel publication. Stable promotion requires the RPM-specific key and an already-published testing snapshot.
