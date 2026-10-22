# Veyra APK Repository

All Veyra-specific APKBUILD recipes and application sources live in src/.
The Go source for vpkg remains in angyedz/Veyra-Linux, which the build checks
out into distro-source/. There are no duplicate app recipes in the distro.

The GitHub Actions packages workflow builds with Alpine 3.22 and abuild,
signs one combined APKINDEX and uploads APK artifacts on every PR.

For signed publishing, configure the GitHub Actions secret
VEYRA_ABUILD_PRIVATE_KEY_B64 in THIS repository. Supply the existing private
key, base64-encoded, whose matching public key is keys/veyra.rsa.pub.
The workflow compares DER encodings of the key pair before release.
If the secret is unavailable, only ephemeral-key CI artifacts are produced.
Never commit a private key; never install APKs with --allow-untrusted.

Successful signed main builds update stable/v1/x86_64 atomically in a
single Git commit, using this repo's built-in GITHUB_TOKEN (contents:write).

Local Alpine build requires alpine-sdk, go, git, an abuild signing key, and
the Veyra-Linux clone at distro-source/. Run: sh scripts/build.sh.

Veyra AppCenter is a Qt Quick interface for signed APK packages, optional
user-scoped Flatpak applications from Flathub, and optional user-scoped Nix.
Alpine Stable and Flathub supply the application catalogs. Flatpak applications
are installed into the current account's home; the system APK lane remains
administrator-managed in Veyra AppCenter. AppCenter supplies both the Alpine
APK catalog and per-user Flathub installs. glenv is a glibc runtime
compatibility environment, not a package manager. The GitHub raw path is a
development mirror and needs CDN validation for production use.
