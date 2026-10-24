# Veyra Linux package repository

This repository contains **only packages maintained specifically for Veyra Linux**. It is not a mirror of Fedora and does not rebuild Fedora's system packages. The installed Veyra system gets its base RPMs, drivers, libraries, and dependency providers from its configured Fedora repositories; `vpkg` can resolve Veyra packages together with those upstream repositories through DNF/libdnf5.

The first Veyra release track is **Veyra Linux pre-alpha**. Fedora's release number is not a Veyra version and is not part of the package repository address. Veyra owns the `testing` and `stable` channels:

- `testing` is for packages being exercised before promotion.
- `stable` is the promoted package channel. The first Veyra system release is still pre-alpha; the branch name does not claim that Veyra Linux 1.0 has shipped.

Each channel branch publishes its repository snapshot under `repo/x86_64/`. The project currently includes a small `veyra-release` RPM to exercise spec parsing, signing, repository metadata generation, and DNF installation end to end. New Veyra components such as `veyra-updater` and `veyra-welcome` belong here when their Fedora-native implementations are ready.

## Channel configuration

The testing repository can be configured with:

```ini
[veyra-testing]
name=Veyra Linux testing packages
baseurl=https://raw.githubusercontent.com/angyedz/veyra-pkgrepo/testing/repo/x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://raw.githubusercontent.com/angyedz/veyra-pkgrepo/testing/repo/x86_64/RPM-GPG-KEY-VEYRA
```

For the stable channel, use branch `stable` and repository ID `veyra-stable`. The raw GitHub URL is a development mirror; a production release needs a separately validated CDN or package host. The public signing key must be pinned by the Veyra image or another trusted bootstrap before enabling this repository. Fetching a key from the same repository it authenticates is not a trust bootstrap.

## Build and signing

Package recipes live in `rpms/<package>/`. Build locally in a Fedora environment with `rpm-build`, `rpm-sign`, `createrepo_c`, and `gnupg2` installed, and a signing key available in `GNUPGHOME`:

```sh
export VEYRA_RPM_GPG_FINGERPRINT=YOUR_SIGNING_KEY_FINGERPRINT
bash scripts/build-rpm-repo.sh /tmp/veyra-repo/x86_64
```

Pull request checks use disposable keys and validate the RPM plus signed repository metadata without publishing. The publishing workflow expects an armored OpenPGP private key, base64-encoded as the GitHub Actions secret `VEYRA_RPM_GPG_PRIVATE_KEY_B64`. It publishes a new signed snapshot into the branch that triggered the workflow, using that branch's own channel. The workflow's built-in `GITHUB_TOKEN` only commits the generated snapshot; it is not a package-signing key.

The legacy `VEYRA_ABUILD_PRIVATE_KEY_B64` key signs APKs and is not an RPM/OpenPGP key. A GitHub Personal Access Token also cannot sign RPM package payloads. Never place either private signing material in the repository. If the RPM-specific secret is absent, the publisher workflow produces a temporary CI artifact and skips branch publication.
