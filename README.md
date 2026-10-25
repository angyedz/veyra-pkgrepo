# Veyra Linux package repository

This repository contains **only packages maintained specifically for Veyra Linux**. It is not a Fedora mirror and does not rebuild Fedora's system packages. Fedora repositories provide the base system, drivers, libraries, and dependency providers. `vpkg` resolves these together with Veyra add-on packages through the libdnf5 API; the Veyra host does not need the DNF command-line client.

The Git repository has one code branch: `main`. Inside the RPM repository there are two **package channels**, also called package branches:

- `testing` contains packages awaiting validation.
- `main` is the promoted, stable package channel. The first Veyra release is still Veyra Linux pre-alpha; this channel name does not claim that Veyra Linux 1.0 has shipped.

These package channels are directories, not Git branches:

- `repo/testing/x86_64/`
- `repo/main/x86_64/`

The repository contains only Veyra-maintained software. Source trees live in `sources/<package>/`; RPM recipes live in `rpms/<package>/`. GitHub Actions builds these sources into signed RPMs and publishes the testing and stable DNF repository snapshots. Fedora remains the separate source for Fedora packages and dependencies; this repository does not mirror Fedora.

Versioned package releases are published as GitHub Releases from tags named `rpm-v<version>` (for example, `rpm-v0.1.0`). A testing prerelease uses the corresponding `rpm-v<version>-testing` tag. Each release contains signed RPM files, the Veyra public signing key, checksums, and a complete signed repository snapshot archive named `veyra-rpm-repo-x86_64.tar.gz`. `vpkg` consumes the signed release snapshot through libdnf5; the raw channel URLs below remain a development mirror.

The repository includes source packages for `veyra-vpkg`, `veyra-update`, and the read-only `veyra-v-dri` diagnostics tool, plus a small `veyra-release` CI package. Vforge is being added as its implementation stabilizes. CI installs the runtime packages and checks that vpkg does not require the DNF command-line client. This repository will not carry the complete Fedora system package set.

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

Package recipes live in `rpms/<package>/`; first-party sources live in `sources/<package>/`. Build locally in a Fedora 44 environment with `rpm-build`, `rpm-sign`, `createrepo_c`, `gnupg2`, and `tar` installed, and a signing key available in `GNUPGHOME`:

```sh
export VEYRA_RPM_GPG_FINGERPRINT=YOUR_SIGNING_KEY_FINGERPRINT
bash scripts/build-rpm-repo.sh /tmp/veyra-repo/x86_64
```

Pull request checks use disposable keys and validate the RPM plus signed repository metadata without publishing. A push to GitHub's `main` code branch builds and publishes the signed `testing` package mirror. After validating that snapshot, dispatch **Publish Veyra RPM repository** from Git branch `main` with package channel `main` to promote the exact RPM files into the stable mirror. To publish downloadable versioned RPM assets, tag a reviewed commit as `rpm-v<version>` or `rpm-v<version>-testing`; the release workflow builds in Fedora 44, verifies the tag is on `main`, signs the packages, and creates a stable release or testing prerelease.

Publishing expects an armored OpenPGP private key, base64-encoded as the GitHub Actions secret `VEYRA_RPM_GPG_PRIVATE_KEY_B64`. The workflow's built-in `GITHUB_TOKEN` only commits generated repository snapshots; it is not a package-signing key. The legacy `VEYRA_ABUILD_PRIVATE_KEY_B64` signs APKs and is not an RPM/OpenPGP key. A GitHub Personal Access Token also cannot sign RPM package payloads. Never place private signing material in the repository.

If the RPM-specific secret is absent, the automatic testing build creates a temporary signed CI artifact and skips channel publication. Stable promotion requires the RPM-specific key and an already-published testing snapshot.
