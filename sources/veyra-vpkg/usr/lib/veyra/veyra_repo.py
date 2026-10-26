"""Fetch and authenticate Veyra RPM repository snapshots from GitHub Releases.

Release assets are only a transport. Trust comes from a pinned SHA256 asset and
the repomd signature made by the image-pinned Veyra RPM key.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.parse import urlparse
from urllib.request import Request, urlopen


REPOSITORY = "angyedz/veyra-pkgrepo"
API_ROOT = f"https://api.github.com/repos/{REPOSITORY}"
ARCHIVE_NAME = "veyra-rpm-repo-x86_64.tar.gz"
CHECKSUM_NAME = "veyra-rpm-repo-x86_64.tar.gz.sha256"
MAX_ASSET_BYTES = 512 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
MAX_MEMBERS = 100_000
_STABLE_TAG = re.compile(r"^rpm-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_TESTING_TAG = re.compile(
    r"^rpm-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-testing$"
)
_DIGEST_LINE = re.compile(
    rb"^([0-9a-fA-F]{64})[ \t]+(?:\*?)veyra-rpm-repo-x86_64\.tar\.gz\r?\n?$"
)


class VeyraRepoError(RuntimeError):
    """The selected Veyra release could not be safely authenticated."""


def _https_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise VeyraRepoError("GitHub returned a non-HTTPS release asset URL.")
    return value


def _request(url: str, *, accept: str = "application/vnd.github+json", opener=urlopen):
    request = Request(
        _https_url(url),
        headers={"Accept": accept, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "veyra-vpkg"},
    )
    response = opener(request, timeout=60)
    final_url = response.geturl()
    if urlparse(final_url).scheme != "https":
        response.close()
        raise VeyraRepoError("GitHub redirected a release asset to a non-HTTPS URL.")
    return response


def _read_limited(response, limit: int) -> bytes:
    declared = response.headers.get("Content-Length")
    if declared and int(declared) > limit:
        raise VeyraRepoError("Release asset exceeds the configured download size limit.")
    chunks = []
    size = 0
    while True:
        block = response.read(min(1024 * 1024, limit + 1 - size))
        if not block:
            break
        size += len(block)
        if size > limit:
            raise VeyraRepoError("Release asset exceeds the configured download size limit.")
        chunks.append(block)
    return b"".join(chunks)


def _release_asset_url(release: dict, name: str) -> str:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise VeyraRepoError("GitHub release metadata has no valid assets list.")
    matches = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == name]
    if len(matches) != 1:
        raise VeyraRepoError(f"Release must contain exactly one {name} asset.")
    return _https_url(matches[0].get("browser_download_url", ""))


def _json_url(url: str, *, opener=urlopen):
    with _request(url, opener=opener) as response:
        try:
            result = json.loads(_read_limited(response, 4 * 1024 * 1024))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise VeyraRepoError("GitHub returned malformed release metadata.") from error
        link = response.headers.get("Link", "")
    return result, link


def select_release(channel: str, *, opener=urlopen) -> dict:
    """Select the latest stable version or greatest testing semver release."""
    if channel not in {"main", "testing"}:
        raise VeyraRepoError(f"Unsupported Veyra package channel: {channel}")

    url = f"{API_ROOT}/releases?per_page=100"
    matches = []
    pages = 0
    pattern = _STABLE_TAG if channel == "main" else _TESTING_TAG
    while url:
        releases, link_header = _json_url(url, opener=opener)
        if not isinstance(releases, list):
            raise VeyraRepoError("GitHub returned malformed testing release metadata.")
        for release in releases:
            if not isinstance(release, dict):
                continue
            tag = release.get("tag_name", "")
            parsed = pattern.fullmatch(tag)
            channel_flag_matches = release.get("prerelease") is (channel == "testing")
            if parsed and channel_flag_matches:
                matches.append((tuple(map(int, parsed.groups())), release))
        pages += 1
        if pages >= 10:
            break
        next_links = [part.strip() for part in link_header.split(",") if 'rel="next"' in part]
        if not next_links:
            break
        candidate = next_links[0].split(";", 1)[0].strip().strip("<>")
        parsed = urlparse(candidate)
        if parsed.scheme != "https" or parsed.hostname != "api.github.com" or not parsed.path.startswith(
            f"/repos/{REPOSITORY}/releases"
        ):
            raise VeyraRepoError("GitHub returned an unsafe release pagination URL.")
        url = candidate
    if not matches:
        expected = "rpm-vX.Y.Z" if channel == "main" else "rpm-vX.Y.Z-testing"
        raise VeyraRepoError(f"No valid {channel} release with tag {expected} was found.")
    return max(matches, key=lambda item: item[0])[1]


def _download_checksum(release: dict, *, opener=urlopen) -> bytes:
    checksum_url = _release_asset_url(release, CHECKSUM_NAME)
    with _request(checksum_url, accept="application/octet-stream", opener=opener) as response:
        return _read_limited(response, 4096)


def _verify_archive_digest(archive: bytes, checksum: bytes) -> str:
    match = _DIGEST_LINE.fullmatch(checksum)
    if not match:
        raise VeyraRepoError("The release archive SHA256 asset has an invalid format.")
    digest = hashlib.sha256(archive).hexdigest()
    if digest != match.group(1).decode("ascii").lower():
        raise VeyraRepoError("The Veyra repository archive SHA256 check failed.")
    return digest


def _safe_extract(archive: bytes, destination: Path) -> None:
    """Extract only ordinary files/directories beneath the x86_64 root."""
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    extracted = 0
    count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for member in tar:
                count += 1
                if count > MAX_MEMBERS:
                    raise VeyraRepoError("Repository archive contains too many entries.")
                name = member.name
                path = PurePosixPath(name)
                if (
                    path.is_absolute()
                    or not path.parts
                    or path.parts[0] != "x86_64"
                    or any(part in {"", ".", ".."} for part in path.parts)
                ):
                    raise VeyraRepoError(f"Repository archive contains an unsafe path: {name!r}")
                if not (member.isdir() or member.isfile()):
                    raise VeyraRepoError(f"Repository archive contains a link or special file: {name!r}")
                extracted += member.size
                if extracted > MAX_EXTRACTED_BYTES:
                    raise VeyraRepoError("Repository archive expands beyond the configured size limit.")
                target = destination.joinpath(*path.parts)
                if member.isdir():
                    target.mkdir(mode=0o755, parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    raise VeyraRepoError(f"Repository archive entry cannot be read: {name!r}")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(target, flags, 0o600)
                with os.fdopen(fd, "wb") as output, source:
                    remaining = member.size
                    while remaining:
                        block = source.read(min(1024 * 1024, remaining))
                        if not block:
                            raise VeyraRepoError(f"Truncated repository archive entry: {name!r}")
                        output.write(block)
                        remaining -= len(block)
                os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
        repo = destination / "x86_64"
        required = (
            repo / "repodata/repomd.xml",
            repo / "repodata/repomd.xml.asc",
            repo / "RPM-GPG-KEY-VEYRA",
        )
        if not all(path.is_file() and not path.is_symlink() for path in required):
            raise VeyraRepoError("Repository archive lacks repomd, its signature, or the RPM key.")
    except (tarfile.TarError, OSError) as error:
        shutil.rmtree(destination, ignore_errors=True)
        if isinstance(error, VeyraRepoError):
            raise
        raise VeyraRepoError(f"Could not safely extract the Veyra repository archive: {error}") from error
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def _key_fingerprints(key_path: Path, home: Path) -> set[str]:
    result = subprocess.run(
        ["gpg", "--batch", "--no-options", "--homedir", str(home), "--import", str(key_path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode:
        raise VeyraRepoError("Could not import the image-pinned Veyra repository key.")
    result = subprocess.run(
        ["gpg", "--batch", "--no-options", "--homedir", str(home), "--with-colons", "--fingerprint"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode:
        raise VeyraRepoError("Could not inspect the image-pinned Veyra repository key.")
    return {
        line.split(":")[9]
        for line in result.stdout.splitlines()
        if line.startswith("fpr:") and len(line.split(":")) > 9
    }


def verify_repomd_signature(repo_root: Path, key_path: Path) -> None:
    metadata = repo_root / "repodata/repomd.xml"
    signature = repo_root / "repodata/repomd.xml.asc"
    if not key_path.is_file() or not metadata.is_file() or not signature.is_file():
        raise VeyraRepoError("Pinned key or signed repository metadata is missing.")
    with tempfile.TemporaryDirectory(prefix="veyra-vpkg-gpg-") as temporary:
        home = Path(temporary)
        os.chmod(home, 0o700)
        fingerprints = _key_fingerprints(key_path, home)
        if not fingerprints:
            raise VeyraRepoError("The pinned Veyra repository key has no fingerprint.")
        result = subprocess.run(
            [
                "gpg", "--batch", "--no-options", "--homedir", str(home), "--status-fd", "1",
                "--verify", str(signature), str(metadata),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        valid_signers = {
            line.split()[2]
            for line in result.stdout.splitlines()
            if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split()) >= 3
        }
        if result.returncode or not (valid_signers & fingerprints):
            raise VeyraRepoError("The Veyra repository metadata signature is invalid or not pinned.")


def _atomic_link(link: Path, target: Path) -> None:
    temporary = link.with_name(f".{link.name}.{os.getpid()}.tmp")
    try:
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(target, target_is_directory=True)
        os.replace(temporary, link)
    finally:
        temporary.unlink(missing_ok=True)


def _prepare_root_owned_cache(cache_root: Path) -> None:
    cache_root.mkdir(mode=0o755, parents=True, exist_ok=True)
    current = Path(cache_root.anchor)
    for part in cache_root.parts[1:]:
        current /= part
        info = current.lstat()
        if not current.is_dir() or current.is_symlink():
            raise VeyraRepoError("Veyra repository cache path contains a symlink or non-directory.")
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise VeyraRepoError("Veyra repository cache must be root-owned and not group/world writable.")


def resolve_repository(
    channel: str,
    cache_root: Path,
    pinned_key: Path,
    *,
    opener=urlopen,
) -> Path:
    """Return a verified local x86_64 repo path, caching immutable releases."""
    release = select_release(channel, opener=opener)
    tag = release.get("tag_name", "")
    expected = _STABLE_TAG if channel == "main" else _TESTING_TAG
    if not expected.fullmatch(tag):
        raise VeyraRepoError("Selected Veyra release tag does not match the requested channel.")
    _prepare_root_owned_cache(cache_root)
    checksum = _download_checksum(release, opener=opener)
    checksum_match = _DIGEST_LINE.fullmatch(checksum)
    if not checksum_match:
        raise VeyraRepoError("The release archive SHA256 asset has an invalid format.")
    digest = checksum_match.group(1).decode("ascii").lower()
    release_root = cache_root / channel / f"{tag}-{digest[:16]}"
    repo_root = release_root / "x86_64"
    if not (repo_root / "repodata/repomd.xml").is_file():
        archive_url = _release_asset_url(release, ARCHIVE_NAME)
        with _request(archive_url, accept="application/octet-stream", opener=opener) as response:
            archive = _read_limited(response, MAX_ASSET_BYTES)
        _verify_archive_digest(archive, checksum)
        staging = cache_root / channel / f".{tag}-{digest[:16]}.staging-{os.getpid()}"
        staging.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if staging.exists():
            shutil.rmtree(staging)
        try:
            _safe_extract(archive, staging)
            verify_repomd_signature(staging / "x86_64", pinned_key)
            os.replace(staging, release_root)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
    # Verify on every use, so cache corruption or a changed key cannot silently
    # expose an old local repository to libdnf5.
    verify_repomd_signature(repo_root, pinned_key)
    channel_link = cache_root / channel / "current"
    _atomic_link(channel_link, release_root)
    return repo_root
