#!/usr/bin/python3
"""Select and mount the ext4-backed vpkg generation before initrd switch-root."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import uuid


ROOTHASH_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
GENERATION_RE = re.compile(r"^generation-[0-9a-f]{32}$")
STATE_RELATIVE = Path("var/lib/veyra/vpkg/system-generations")
SYSTEM_TRIAL_RELATIVE = Path("var/lib/veyra/vpkg/system-trial.json")


class InitrdError(RuntimeError):
    pass


def parse_os_release(data: bytes) -> dict[str, str]:
    try:
        lines = data.decode("utf-8", errors="strict").splitlines()
    except UnicodeError as error:
        raise InitrdError("The selected UKI has a malformed .osrel section.") from error
    values: dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        if key not in {"ID", "VERSION_ID", "IMAGE_VERSION"}:
            continue
        if key in values:
            raise InitrdError(f"The selected UKI .osrel repeats {key}.")
        value = raw_value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        if not value or any(c in value for c in "\x00\n\r"):
            raise InitrdError(f"The selected UKI .osrel has an invalid {key}.")
        values[key] = value
    if set(values) != {"ID", "VERSION_ID", "IMAGE_VERSION"}:
        raise InitrdError("The selected UKI .osrel must define ID, VERSION_ID, and IMAGE_VERSION.")
    if values["ID"] != "fedora" or values["VERSION_ID"] != "44":
        raise InitrdError("The vpkg initrd generation backend currently supports Fedora 44 only.")
    if not VERSION_RE.fullmatch(values["IMAGE_VERSION"]):
        raise InitrdError("The selected UKI .osrel has an unsafe IMAGE_VERSION.")
    return values


def read_uki_image_version(uki: Path) -> str:
    try:
        size = uki.stat().st_size
        with uki.open("rb") as stream:
            header = stream.read(64)
            if len(header) < 64 or header[:2] != b"MZ":
                raise ValueError("missing DOS header")
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            if pe_offset + 24 > size:
                raise ValueError("truncated PE header")
            stream.seek(pe_offset)
            coff = stream.read(24)
            if len(coff) != 24 or coff[:4] != b"PE\0\0":
                raise ValueError("missing PE header")
            section_count = struct.unpack_from("<H", coff, 6)[0]
            optional_size = struct.unpack_from("<H", coff, 20)[0]
            table_offset = pe_offset + 24 + optional_size
            if not 0 < section_count <= 96 or optional_size > 4096:
                raise ValueError("invalid PE dimensions")
            if table_offset + section_count * 40 > size:
                raise ValueError("truncated PE section table")
            osrel_section: tuple[int, int] | None = None
            stream.seek(table_offset)
            for _ in range(section_count):
                section = stream.read(40)
                if len(section) != 40:
                    raise ValueError("truncated PE section table")
                name = section[:8].split(b"\0", 1)[0]
                if name == b".osrel":
                    raw_size, raw_offset = struct.unpack_from("<II", section, 16)
                    if not raw_size or raw_size > 1024 * 1024 or raw_offset + raw_size > size:
                        raise ValueError("invalid .osrel section size")
                    osrel_section = (raw_offset, raw_size)
            if osrel_section is None:
                raise ValueError("missing .osrel section")
            stream.seek(osrel_section[0])
            osrel = parse_os_release(stream.read(osrel_section[1]).split(b"\0", 1)[0])
            return osrel["IMAGE_VERSION"]
    except (OSError, ValueError, struct.error) as error:
        raise InitrdError(f"Cannot read the selected UKI identity from {uki}: {error}") from error


def deployment_identity(command_line: str, uki: Path) -> tuple[str, str]:
    hashes = [token.partition("=")[2] for token in command_line.split() if token.startswith("roothash=")]
    if len(hashes) != 1 or not ROOTHASH_RE.fullmatch(hashes[0]):
        raise InitrdError("The running UKI must provide exactly one valid roothash.")
    return hashes[0], read_uki_image_version(uki)


def safe_generation_id(value: str) -> str:
    if not GENERATION_RE.fullmatch(value):
        raise InitrdError("The active vpkg system-generation pointer is malformed.")
    return value


def ensure_real_directory(path: Path, mode: int = 0o700) -> None:
    absolute = path.absolute()
    cursor = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        cursor = cursor / component
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            cursor.mkdir(mode=mode)
            info = cursor.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise InitrdError(f"Refusing a symlink in vpkg generation state: {cursor}")
        if not stat.S_ISDIR(info.st_mode):
            raise InitrdError(f"Vpkg generation state is not a directory: {cursor}")
    info = absolute.lstat()
    if os.geteuid() == 0 and info.st_uid != 0:
        raise InitrdError(f"Vpkg generation state is not root-owned: {absolute}")
    if info.st_mode & 0o022:
        raise InitrdError(f"Vpkg generation state is group- or world-writable: {absolute}")


def validate_tree_for_copy(source: Path) -> None:
    if source.is_symlink() or not source.is_dir():
        raise InitrdError(f"The base RPM database is missing or is not a real directory: {source}")
    for current, directories, filenames in os.walk(source, followlinks=False):
        current_path = Path(current)
        for name in directories + filenames:
            path = current_path / name
            info = path.lstat()
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise InitrdError(f"The base RPM database contains an unsupported file: {path}")


def require_real_directories(generation: Path, relatives: tuple[str, ...]) -> None:
    for relative in relatives:
        path = generation / relative
        try:
            info = path.lstat()
        except OSError as error:
            raise InitrdError(f"The vpkg system generation is missing {relative}.") from error
        if not stat.S_ISDIR(info.st_mode):
            raise InitrdError(f"The vpkg system generation has an unsafe {relative}.")


def read_active_generation(identity_dir: Path, roothash: str, image_version: str) -> Path | None:
    active = identity_dir / "active"
    if not active.is_symlink():
        if active.exists():
            raise InitrdError("The vpkg active system-generation selector is not a symlink.")
        return None
    generation_id = safe_generation_id(os.readlink(active))
    generation = identity_dir / generation_id
    if generation.is_symlink() or not generation.is_dir():
        raise InitrdError("The active vpkg system generation is unavailable.")
    try:
        manifest = json.loads((generation / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InitrdError("The active vpkg system-generation manifest is unreadable.") from error
    expected = {"schema": 1, "generation_id": generation_id, "base_roothash": roothash,
                "uki_image_version": image_version}
    if not isinstance(manifest, dict) or any(manifest.get(key) != value for key, value in expected.items()):
        raise InitrdError("The active vpkg system generation belongs to a different deployment identity.")
    require_real_directories(generation, (
        "upper", "upper/usr", "upper/etc", "upper/usr/lib",
        "upper/usr/lib/sysimage", "upper/usr/lib/sysimage/rpm",
        "work", "work/usr", "work/etc",
    ))
    rpmdb = generation / "upper/usr/lib/sysimage/rpm"
    if manifest.get("rpmdb_sha256") != rpmdb_digest(rpmdb):
        raise InitrdError("The active vpkg generation RPM database failed its integrity check.")
    if manifest.get("usr_upper_sha256") != generation_usr_digest(generation / "upper/usr"):
        raise InitrdError("The active vpkg generation /usr upper failed its integrity check.")
    return generation


def rpmdb_digest(rpmdb: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(rpmdb.rglob("*")):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise InitrdError(f"The generation RPM database contains an unsupported entry: {path}")
        digest.update(path.relative_to(rpmdb).as_posix().encode("utf-8") + b"\0")
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    return digest.hexdigest()


def generation_usr_digest(usr_upper: Path) -> str:
    """Hash the immutable /usr upper, including OverlayFS whiteouts and xattrs."""
    if usr_upper.is_symlink() or not usr_upper.is_dir():
        raise InitrdError("The system generation /usr upper is not a real directory.")
    digest = hashlib.sha256()
    entries = [usr_upper]
    for current, directories, filenames in os.walk(usr_upper, followlinks=False):
        current_path = Path(current)
        entries.extend(current_path / name for name in directories)
        entries.extend(current_path / name for name in filenames)
    for path in sorted(entries, key=lambda entry: entry.relative_to(usr_upper.parent).as_posix()):
        info = path.lstat()
        relative = path.relative_to(usr_upper.parent).as_posix().encode("utf-8")
        if stat.S_ISDIR(info.st_mode):
            kind = b"d"
        elif stat.S_ISREG(info.st_mode):
            kind = b"f"
        elif stat.S_ISLNK(info.st_mode):
            kind = b"l"
        elif stat.S_ISCHR(info.st_mode) and info.st_rdev == 0:
            kind = b"w"  # OverlayFS whiteout represented as character device 0/0.
        else:
            raise InitrdError(f"The generation /usr upper has an unsupported entry: {path}")
        digest.update(kind + b"\0" + relative + b"\0")
        digest.update(f"{stat.S_IMODE(info.st_mode):o}:{info.st_uid}:{info.st_gid}".encode("ascii") + b"\0")
        if stat.S_ISREG(info.st_mode):
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
        elif stat.S_ISLNK(info.st_mode):
            digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
        try:
            attributes = sorted(os.listxattr(path, follow_symlinks=False))
        except OSError as error:
            raise InitrdError(f"Could not inspect generation xattrs for {path}: {error}") from error
        for attribute in attributes:
            try:
                value = os.getxattr(path, attribute, follow_symlinks=False)
            except OSError as error:
                raise InitrdError(f"Could not read generation xattr {attribute} on {path}: {error}") from error
            digest.update(attribute.encode("utf-8", errors="surrogateescape") + b"\0" + value + b"\0")
    return digest.hexdigest()


def fsync_tree(root: Path) -> None:
    directories: list[Path] = []
    files: list[Path] = []
    for current, names, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories.append(current_path)
        for name in names:
            entry = current_path / name
            if not entry.is_symlink():
                directories.append(entry)
        for name in filenames:
            entry = current_path / name
            if not entry.is_symlink():
                files.append(entry)
    for path in files:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for path in reversed(directories):
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def read_generation(identity_dir: Path, generation_id: str, roothash: str, image_version: str) -> Path:
    generation_id = safe_generation_id(generation_id)
    generation = identity_dir / generation_id
    if generation.is_symlink() or not generation.is_dir():
        raise InitrdError("The requested vpkg system generation is unavailable.")
    try:
        manifest = json.loads((generation / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InitrdError("The requested vpkg system-generation manifest is unreadable.") from error
    expected = {"schema": 1, "generation_id": generation_id, "base_roothash": roothash,
                "uki_image_version": image_version}
    if not isinstance(manifest, dict) or any(manifest.get(key) != value for key, value in expected.items()):
        raise InitrdError("The requested vpkg system generation belongs to a different deployment identity.")
    require_real_directories(generation, (
        "upper", "upper/usr", "upper/etc", "upper/usr/lib",
        "upper/usr/lib/sysimage", "upper/usr/lib/sysimage/rpm",
        "work", "work/usr", "work/etc",
    ))
    rpmdb = generation / "upper/usr/lib/sysimage/rpm"
    if manifest.get("rpmdb_sha256") != rpmdb_digest(rpmdb):
        raise InitrdError("The requested vpkg system generation has an invalid RPM database.")
    if manifest.get("usr_upper_sha256") != generation_usr_digest(generation / "upper/usr"):
        raise InitrdError("The requested vpkg generation /usr upper has an invalid integrity digest.")
    return generation


def generation_from_cmdline(command_line: str) -> str | None:
    values = [token.partition("=")[2] for token in command_line.split()
              if token.startswith("veyra.vpkg-generation=")]
    if not values:
        return None
    if len(values) != 1:
        raise InitrdError("The UKI must provide at most one vpkg generation selector.")
    return safe_generation_id(values[0])


def read_system_trial(sysroot: Path) -> dict[str, object] | None:
    path = sysroot / SYSTEM_TRIAL_RELATIVE
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_file():
        raise InitrdError("The vpkg system-generation trial marker is not a regular file.")
    info = path.lstat()
    if os.geteuid() == 0 and (info.st_uid != 0 or info.st_mode & 0o077):
        raise InitrdError("The vpkg system-generation trial marker is not private root-owned state.")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InitrdError("The vpkg system-generation trial marker is unreadable.") from error
    if not isinstance(value, dict):
        raise InitrdError("The vpkg system-generation trial marker is malformed.")
    roothash = value.get("roothash")
    version = value.get("version")
    generation_id = value.get("generation_id")
    parent_id = value.get("parent_generation")
    origin_boot_id = value.get("origin_boot_id")
    attempts = value.get("attempts")
    state = value.get("state")
    try:
        valid_boot_id = isinstance(origin_boot_id, str) and str(uuid.UUID(origin_boot_id)) == origin_boot_id
    except ValueError:
        valid_boot_id = False
    if (
        value.get("schema") != 1
        or value.get("kind") != "system-generation"
        or not isinstance(roothash, str)
        or not ROOTHASH_RE.fullmatch(roothash)
        or not isinstance(version, str)
        or not VERSION_RE.fullmatch(version)
        or not isinstance(generation_id, str)
        or not GENERATION_RE.fullmatch(generation_id)
        or not isinstance(parent_id, str)
        or not GENERATION_RE.fullmatch(parent_id)
        or not valid_boot_id
        or type(attempts) is not int
        or attempts not in {0, 1}
        or state not in {"pending", "committing", "failed"}
    ):
        raise InitrdError("The vpkg system-generation trial marker is malformed.")
    return value


def write_system_trial(sysroot: Path, marker: dict[str, object]) -> None:
    path = sysroot / SYSTEM_TRIAL_RELATIVE
    ensure_real_directory(path.parent)
    temporary = path.parent / f".system-trial-{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(marker, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise InitrdError(f"Could not durably write the vpkg system-generation trial marker: {error}") from error


def remove_system_trial(sysroot: Path) -> None:
    path = sysroot / SYSTEM_TRIAL_RELATIVE
    if path.is_symlink():
        raise InitrdError("Refusing to remove a symlinked vpkg system-generation trial marker.")
    path.unlink(missing_ok=True)
    if path.parent.is_dir():
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def remove_generation_directory(identity_dir: Path, generation_id: str) -> None:
    generation_id = safe_generation_id(generation_id)
    absolute_identity = identity_dir.absolute()
    cursor = Path(absolute_identity.anchor)
    for component in absolute_identity.parts[1:]:
        cursor /= component
        if cursor.is_symlink():
            raise InitrdError("The system-generation identity path contains a symlink.")
    if not identity_dir.is_dir():
        raise InitrdError("The system-generation identity directory is unsafe.")
    generation = identity_dir / generation_id
    try:
        info = generation.lstat()
    except FileNotFoundError:
        return
    if (not stat.S_ISDIR(info.st_mode)
            or os.geteuid() == 0 and info.st_uid != 0
            or info.st_mode & 0o022):
        raise InitrdError("The system-generation candidate is not a private root-owned directory.")
    device = info.st_dev
    for current, directories, filenames in os.walk(generation, followlinks=False):
        for name in directories + filenames:
            entry = Path(current) / name
            entry_info = entry.lstat()
            if entry_info.st_dev != device:
                raise InitrdError("Refusing to recursively remove a mounted system-generation candidate.")
            if (stat.S_ISDIR(entry_info.st_mode)
                    and (os.geteuid() == 0 and entry_info.st_uid != 0 or entry_info.st_mode & 0o022)):
                raise InitrdError("The system-generation candidate contains an unsafe directory.")
    shutil.rmtree(generation)
    directory_fd = os.open(identity_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def set_active_generation(identity_dir: Path, generation_id: str) -> None:
    generation_id = safe_generation_id(generation_id)
    generation = identity_dir / generation_id
    if generation.is_symlink() or not generation.is_dir():
        raise InitrdError("Cannot select an unavailable vpkg system generation.")
    temporary = identity_dir / f".active-{uuid.uuid4().hex}"
    temporary.symlink_to(generation_id, target_is_directory=True)
    os.replace(temporary, identity_dir / "active")
    directory_fd = os.open(identity_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def mark_generation_active(generation: Path) -> None:
    manifest_path = generation / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("state") == "active":
        return
    manifest["state"] = "active"
    temporary = generation / f".manifest-{uuid.uuid4().hex}.tmp"
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, manifest_path)
    fsync_tree(generation)


def create_trial_generation(sysroot: Path, roothash: str, image_version: str) -> Path:
    identity_dir = sysroot / STATE_RELATIVE / f"{roothash}--{image_version}"
    ensure_real_directory(identity_dir)
    parent = read_active_generation(identity_dir, roothash, image_version)
    if parent is None:
        raise InitrdError("A system-package candidate requires an initialized active generation.")
    generation_id = f"generation-{uuid.uuid4().hex}"
    generation = identity_dir / generation_id
    ensure_real_directory(generation)
    for relative in ("usr", "etc"):
        ensure_real_directory(generation / "upper" / relative)
    for relative in ("usr", "etc"):
        ensure_real_directory(generation / "work" / relative)
    parent_rpmdb = parent / "upper/usr/lib/sysimage/rpm"
    if parent_rpmdb.is_symlink() or not parent_rpmdb.is_dir():
        shutil.rmtree(generation, ignore_errors=True)
        raise InitrdError("The active system generation has no generation-owned RPM database.")
    rpmdb = generation / "upper/usr/lib/sysimage/rpm"
    ensure_real_directory(rpmdb.parent)
    shutil.copytree(parent_rpmdb, rpmdb, symlinks=False)
    manifest = {
        "schema": 1,
        "generation_id": generation_id,
        "parent_generation": parent.name,
        "base_roothash": roothash,
        "uki_image_version": image_version,
        "rpmdb_path": "upper/usr/lib/sysimage/rpm",
        "upper_dirs": ["upper/usr", "upper/etc"],
        "work_dirs": ["work/usr", "work/etc"],
        "rpmdb_sha256": rpmdb_digest(rpmdb),
        "usr_upper_sha256": generation_usr_digest(generation / "upper/usr"),
        "state": "trial",
    }
    manifest_path = generation / "manifest.json"
    with manifest_path.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    fsync_tree(generation)
    return generation


def seal_trial_generation(sysroot: Path, roothash: str, image_version: str,
                          generation_id: str) -> Path:
    identity_dir = sysroot / STATE_RELATIVE / f"{roothash}--{image_version}"
    generation_id = safe_generation_id(generation_id)
    generation = identity_dir / generation_id
    if generation.is_symlink() or not generation.is_dir():
        raise InitrdError("The system-generation candidate is unavailable for sealing.")
    try:
        manifest = json.loads((generation / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InitrdError("The system-generation candidate manifest is unreadable.") from error
    parent = read_active_generation(identity_dir, roothash, image_version)
    if (not isinstance(manifest, dict) or manifest.get("generation_id") != generation_id
            or manifest.get("base_roothash") != roothash
            or manifest.get("uki_image_version") != image_version
            or manifest.get("parent_generation") != (parent.name if parent else None)
            or manifest.get("state") != "trial"):
        raise InitrdError("The system-generation candidate does not match the active parent identity.")
    rpmdb = generation / "upper/usr/lib/sysimage/rpm"
    manifest["rpmdb_sha256"] = rpmdb_digest(rpmdb)
    manifest["usr_upper_sha256"] = generation_usr_digest(generation / "upper/usr")
    temporary = generation / f".manifest-{uuid.uuid4().hex}.tmp"
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, generation / "manifest.json")
    fsync_tree(generation)
    return generation


def select_generation_for_boot(sysroot: Path, roothash: str, image_version: str,
                               command_line: str, boot_id: str | None = None) -> Path:
    identity_dir = sysroot / STATE_RELATIVE / f"{roothash}--{image_version}"
    requested_id = generation_from_cmdline(command_line)
    if requested_id is not None:
        return read_generation(identity_dir, requested_id, roothash, image_version)
    generation = ensure_base_generation(sysroot, roothash, image_version)
    active = read_active_generation(identity_dir, roothash, image_version)
    if active is None or active != generation:
        raise InitrdError("The active vpkg system generation changed while selecting the boot layer.")
    marker = read_system_trial(sysroot)
    if (
        marker is not None
        and marker["roothash"] == roothash
        and marker["version"] == image_version
        and marker["state"] == "committing"
    ):
        candidate = read_generation(identity_dir, str(marker["generation_id"]), roothash, image_version)
        parent_id = marker["parent_generation"]
        if active.name == marker["generation_id"]:
            mark_generation_active(candidate)
            remove_system_trial(sysroot)
            return candidate
        if active.name == parent_id:
            mark_generation_active(candidate)
            set_active_generation(identity_dir, candidate.name)
            remove_system_trial(sysroot)
            return candidate
        marker["state"] = "failed"
        write_system_trial(sysroot, marker)
        return generation
    if (
        marker is None
        or marker["roothash"] != roothash
        or marker["version"] != image_version
        or marker["state"] != "pending"
        or boot_id == marker["origin_boot_id"]
    ):
        return generation
    if marker["attempts"] == 1:
        marker["state"] = "failed"
        write_system_trial(sysroot, marker)
        return generation
    try:
        candidate = read_generation(identity_dir, str(marker["generation_id"]), roothash, image_version)
    except InitrdError:
        marker["state"] = "failed"
        write_system_trial(sysroot, marker)
        return generation
    manifest = json.loads((candidate / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("parent_generation") != active.name or marker["parent_generation"] != active.name:
        marker["state"] = "failed"
        write_system_trial(sysroot, marker)
        return generation
    marker["attempts"] = 1
    write_system_trial(sysroot, marker)
    return candidate
    return generation


def complete_trial_generation(sysroot: Path, roothash: str, image_version: str,
                              generation_id: str) -> None:
    identity_dir = sysroot / STATE_RELATIVE / f"{roothash}--{image_version}"
    generation = read_generation(identity_dir, generation_id, roothash, image_version)
    manifest = json.loads((generation / "manifest.json").read_text(encoding="utf-8"))
    active = read_active_generation(identity_dir, roothash, image_version)
    parent_id = manifest.get("parent_generation")
    if not isinstance(parent_id, str) or active is None or active.name != parent_id:
        raise InitrdError("The trial generation parent is no longer the active generation.")
    manifest["state"] = "active"
    temporary = generation / ".manifest.json.tmp"
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, generation / "manifest.json")
    fsync_tree(generation)
    set_active_generation(identity_dir, generation.name)


def complete_system_trial(sysroot: Path, roothash: str, image_version: str,
                          boot_id: str) -> Path | None:
    marker = read_system_trial(sysroot)
    if marker is None or marker["state"] not in {"pending", "committing"}:
        return None
    if marker["roothash"] != roothash or marker["version"] != image_version:
        return None
    if marker["state"] == "pending" and (
        marker["attempts"] != 1 or marker["origin_boot_id"] == boot_id
    ):
        raise InitrdError("The vpkg system-generation trial has not booted as a candidate.")
    identity_dir = sysroot / STATE_RELATIVE / f"{roothash}--{image_version}"
    generation = read_generation(identity_dir, str(marker["generation_id"]), roothash, image_version)
    active = read_active_generation(identity_dir, roothash, image_version)
    if active is None or active.name not in {marker["parent_generation"], marker["generation_id"]}:
        raise InitrdError("The vpkg system-generation trial parent is no longer active.")
    if generation.name != marker["generation_id"]:
        raise InitrdError("The vpkg system-generation trial candidate identity changed.")
    if active.name != generation.name:
        marker["state"] = "committing"
        write_system_trial(sysroot, marker)
        mark_generation_active(generation)
        set_active_generation(identity_dir, generation.name)
    remove_system_trial(sysroot)
    return generation


def rollback_generation(sysroot: Path, roothash: str, image_version: str) -> Path:
    identity_dir = sysroot / STATE_RELATIVE / f"{roothash}--{image_version}"
    active = read_active_generation(identity_dir, roothash, image_version)
    if active is None:
        raise InitrdError("There is no active vpkg system generation to roll back.")
    manifest = json.loads((active / "manifest.json").read_text(encoding="utf-8"))
    parent_id = manifest.get("parent_generation")
    if not isinstance(parent_id, str):
        raise InitrdError("The active vpkg system generation has no rollback parent.")
    parent = read_generation(identity_dir, parent_id, roothash, image_version)
    set_active_generation(identity_dir, parent.name)
    return parent


def cancel_unbooted_trial(sysroot: Path, roothash: str, image_version: str,
                          boot_id: str) -> None:
    marker = read_system_trial(sysroot)
    if marker is None:
        raise InitrdError("There is no pending vpkg system-generation trial to cancel.")
    if (marker["state"] != "pending" or marker["attempts"] != 0
            or marker["origin_boot_id"] != boot_id
            or marker["roothash"] != roothash or marker["version"] != image_version):
        raise InitrdError("Only an unbooted trial for the current deployment can be cancelled directly.")
    identity_dir = sysroot / STATE_RELATIVE / f"{roothash}--{image_version}"
    active = read_active_generation(identity_dir, roothash, image_version)
    if active is None or active.name != marker["parent_generation"]:
        raise InitrdError("The original active generation changed; refusing trial cancellation.")
    candidate_id = safe_generation_id(str(marker["generation_id"]))
    remove_system_trial(sysroot)
    remove_generation_directory(identity_dir, candidate_id)


def ensure_base_generation(sysroot: Path, roothash: str, image_version: str) -> Path:
    if not ROOTHASH_RE.fullmatch(roothash) or not VERSION_RE.fullmatch(image_version):
        raise InitrdError("The deployment identity is malformed.")
    state_root = sysroot / STATE_RELATIVE
    ensure_real_directory(state_root)
    identity_dir = state_root / f"{roothash}--{image_version}"
    ensure_real_directory(identity_dir)
    active_generation = read_active_generation(identity_dir, roothash, image_version)
    if active_generation is not None:
        return active_generation

    base_rpmdb = sysroot / "usr/lib/sysimage/rpm"
    validate_tree_for_copy(base_rpmdb)
    generation_id = f"generation-{uuid.uuid4().hex}"
    generation = identity_dir / generation_id
    ensure_real_directory(generation)
    upper_usr = generation / "upper/usr"
    upper_etc = generation / "upper/etc"
    work_usr = generation / "work/usr"
    work_etc = generation / "work/etc"
    ensure_real_directory(upper_usr)
    ensure_real_directory(upper_etc)
    ensure_real_directory(work_usr)
    ensure_real_directory(work_etc)
    target_rpmdb = upper_usr / "lib/sysimage/rpm"
    ensure_real_directory(target_rpmdb.parent)
    shutil.copytree(base_rpmdb, target_rpmdb, symlinks=False)
    manifest = {
        "schema": 1,
        "generation_id": generation_id,
        "parent_generation": None,
        "base_roothash": roothash,
        "uki_image_version": image_version,
        "rpmdb_path": "upper/usr/lib/sysimage/rpm",
        "upper_dirs": ["upper/usr", "upper/etc"],
        "work_dirs": ["work/usr", "work/etc"],
        "rpmdb_sha256": rpmdb_digest(target_rpmdb),
        "usr_upper_sha256": generation_usr_digest(upper_usr),
    }
    manifest_tmp = generation / ".manifest.json.tmp"
    with manifest_tmp.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(manifest_tmp, generation / "manifest.json")
    fsync_tree(generation)
    set_active_generation(identity_dir, generation_id)
    return generation


def generation_parent_layers(
    generation: Path, roothash: str, image_version: str
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    identity_dir = generation.parent
    manifest = json.loads((generation / "manifest.json").read_text(encoding="utf-8"))
    parent_id = manifest.get("parent_generation")
    usr_layers: list[Path] = []
    etc_layers: list[Path] = []
    seen = {generation.name}
    while parent_id is not None:
        if not isinstance(parent_id, str) or parent_id in seen:
            raise InitrdError("The vpkg system-generation parent chain is malformed or cyclic.")
        seen.add(parent_id)
        parent = read_generation(identity_dir, parent_id, roothash, image_version)
        usr_layers.append(parent / "upper/usr")
        etc_layers.append(parent / "upper/etc")
        parent_manifest = json.loads((parent / "manifest.json").read_text(encoding="utf-8"))
        parent_id = parent_manifest.get("parent_generation")
    return tuple(usr_layers), tuple(etc_layers)


def mount_generation(
    sysroot: Path,
    generation: Path,
    *,
    parent_usr_layers: tuple[Path, ...] = (),
    parent_etc_layers: tuple[Path, ...] = (),
) -> None:
    mounts = (
        ("usr", generation / "upper/usr", generation / "work/usr", parent_usr_layers),
        ("etc", generation / "upper/etc", generation / "work/etc", parent_etc_layers),
    )
    mounted: list[Path] = []
    try:
        for name, upper, work, parents in mounts:
            lower = sysroot / name
            if lower.is_symlink() or not lower.is_dir():
                raise InitrdError(f"The selected base has no real /{name} directory.")
            for path in (upper, work):
                if path.is_symlink() or not path.is_dir():
                    raise InitrdError(f"The active vpkg generation has an unsafe /{name} layer.")
            if upper.stat().st_dev != work.stat().st_dev:
                raise InitrdError(f"The /{name} OverlayFS upper and work directories must share a filesystem.")
            for parent in parents:
                if parent.is_symlink() or not parent.is_dir() or parent.stat().st_dev != upper.stat().st_dev:
                    raise InitrdError(f"The /{name} parent generation layer is unavailable or on another filesystem.")
            lower_directories = [str(path) for path in parents] + [str(lower)]
            read_only = ",ro" if name == "usr" else ""
            subprocess.run(
                ["mount", "-t", "overlay", "overlay", "-o",
                 f"lowerdir={':'.join(lower_directories)},upperdir={upper},workdir={work},"
                 f"index=off,metacopy=off,redirect_dir=off{read_only}", str(lower)],
                check=True,
            )
            mounted.append(lower)
    except (OSError, subprocess.CalledProcessError, InitrdError) as error:
        for mountpoint in reversed(mounted):
            subprocess.run(["umount", str(mountpoint)], check=False)
        if isinstance(error, InitrdError):
            raise
        raise InitrdError(f"Could not mount the selected vpkg system generation: {error}") from error


def mount_trial_installroot(sysroot: Path, generation: Path, installroot: Path) -> tuple[Path, ...]:
    ensure_real_directory(installroot)
    mounts: list[Path] = []
    for name in ("usr", "etc"):
        target = installroot / name
        ensure_real_directory(target)
        upper = generation / f"upper/{name}"
        work = generation / f".transaction-work/{name}"
        ensure_real_directory(work)
        lower = sysroot / name
        if lower.is_symlink() or not lower.is_dir():
            raise InitrdError(f"The running base has no real /{name} directory.")
        if upper.stat().st_dev != work.stat().st_dev:
            raise InitrdError(f"The staged /{name} OverlayFS upper and work directories must share a filesystem.")
        try:
            subprocess.run(
                ["mount", "-t", "overlay", "overlay", "-o",
                 f"lowerdir={lower},upperdir={upper},workdir={work},"
                 "index=off,metacopy=off,redirect_dir=off", str(target)],
                check=True,
            )
            mounts.append(target)
        except (OSError, subprocess.CalledProcessError) as error:
            unmount_trial_installroot(mounts)
            raise InitrdError(f"Could not mount the staged /{name} RPM transaction root: {error}") from error
    return tuple(mounts)


def unmount_trial_installroot(mounts: tuple[Path, ...] | list[Path]) -> None:
    errors: list[str] = []
    for mountpoint in reversed(mounts):
        try:
            subprocess.run(["umount", str(mountpoint)], check=True)
        except (OSError, subprocess.CalledProcessError) as error:
            errors.append(f"{mountpoint}: {error}")
    if errors:
        raise InitrdError("Could not unmount the staged RPM transaction root: " + "; ".join(errors))


def selected_uki_path(
    sysroot: Path,
    *,
    efi_roots: tuple[Path, ...] = (
        Path("/sysefi"), Path("/efi"), Path("/boot"), Path("/boot/efi")
    ),
) -> Path:
    try:
        result = subprocess.run(
            ["bootctl", "--print-stub-path"],
            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise InitrdError(f"Cannot determine which UKI is booting this deployment: {error}") from error
    raw = result.stdout.strip()
    reported = Path(raw)
    if not reported.is_absolute():
        raise InitrdError("bootctl returned a non-absolute path to the selected UKI.")

    candidates: list[tuple[Path, Path]] = []
    for esp_root in efi_roots:
        try:
            root = esp_root.resolve(strict=True)
        except OSError:
            continue
        if not root.is_dir():
            continue
        # systemd versions may report an ESP-root-relative path (/EFI/...) or
        # the mounted path (/efi/EFI/...).  Resolve both forms only beneath a
        # known mounted ESP root; never reinterpret an arbitrary absolute path.
        if reported.is_relative_to(esp_root) or reported.is_relative_to(root):
            candidates.append((reported, root))
        else:
            candidates.append((root / reported.relative_to("/"), root))

    for candidate, root in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            if resolved.is_relative_to(root) and resolved.is_file():
                return resolved
        except OSError:
            continue
    raise InitrdError(
        "The selected UKI is not readable under a mounted EFI System Partition: "
        f"{reported} (sysroot {sysroot})"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sysroot", type=Path, default=Path("/sysroot"))
    parser.add_argument("--cmdline", type=Path, default=Path("/proc/cmdline"))
    parser.add_argument("--prepare-trial", action="store_true")
    parser.add_argument("--print-parent-layers", action="store_true")
    parser.add_argument("--seal-trial", action="store_true")
    parser.add_argument("--complete-system-trial", action="store_true")
    parser.add_argument("--discard-failed-trial", action="store_true")
    parser.add_argument("--cancel-unbooted-trial", action="store_true")
    parser.add_argument("--rollback-system-generation", action="store_true")
    parser.add_argument("--roothash")
    parser.add_argument("--image-version")
    parser.add_argument("--generation-id")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise InitrdError("The vpkg system-generation helper must run as root.")
        sysroot = args.sysroot.resolve(strict=True)
        helper_operations = (
            args.prepare_trial, args.print_parent_layers, args.seal_trial, args.complete_system_trial,
            args.discard_failed_trial, args.cancel_unbooted_trial,
            args.rollback_system_generation,
        )
        if any(helper_operations):
            if sum(helper_operations) != 1:
                raise InitrdError("Choose only one vpkg system-generation helper operation.")
            if not args.roothash or not args.image_version:
                raise InitrdError("Updating a vpkg trial requires roothash and IMAGE_VERSION.")
            if args.prepare_trial:
                if args.generation_id:
                    raise InitrdError("Preparing a trial does not accept a generation ID.")
                generation = create_trial_generation(sysroot, args.roothash, args.image_version)
                print(generation, flush=True)
                return 0
            if args.print_parent_layers:
                if not args.generation_id:
                    raise InitrdError("Reading generation parent layers requires a generation ID.")
                identity_dir = sysroot / STATE_RELATIVE / f"{args.roothash}--{args.image_version}"
                generation = read_generation(
                    identity_dir, args.generation_id, args.roothash, args.image_version
                )
                usr_layers, etc_layers = generation_parent_layers(
                    generation, args.roothash, args.image_version
                )
                print(json.dumps({
                    "usr": [str(path) for path in usr_layers],
                    "etc": [str(path) for path in etc_layers],
                }, sort_keys=True), flush=True)
                return 0
            if args.seal_trial:
                if not args.generation_id:
                    raise InitrdError("Sealing a trial requires its generation ID.")
                generation = seal_trial_generation(
                    sysroot, args.roothash, args.image_version, args.generation_id
                )
                print(generation, flush=True)
                return 0
            if args.generation_id:
                raise InitrdError("This system-generation operation does not accept a generation ID.")
            if args.complete_system_trial:
                generation = complete_system_trial(
                    sysroot,
                    args.roothash,
                    args.image_version,
                    Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip().lower(),
                )
                print(generation or "no-pending-trial", flush=True)
                return 0
            if args.cancel_unbooted_trial:
                boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip().lower()
                cancel_unbooted_trial(sysroot, args.roothash, args.image_version, boot_id)
                print("cancelled-unbooted-trial", flush=True)
                return 0
            if args.rollback_system_generation:
                marker = read_system_trial(sysroot)
                if marker is not None:
                    raise InitrdError("A system-generation trial must be recovered or cancelled before rollback.")
                generation = rollback_generation(sysroot, args.roothash, args.image_version)
                print(generation, flush=True)
                return 0
            marker = read_system_trial(sysroot)
            if marker is None or marker["state"] != "failed":
                raise InitrdError("Only a failed system-generation trial may be discarded.")
            if marker["roothash"] != args.roothash or marker["version"] != args.image_version:
                raise InitrdError("The failed system-generation trial belongs to a different deployment.")
            identity_dir = sysroot / STATE_RELATIVE / f"{args.roothash}--{args.image_version}"
            active = read_active_generation(identity_dir, args.roothash, args.image_version)
            if active is None or active.name != marker["parent_generation"]:
                raise InitrdError("The old active system generation is not selected; refusing cleanup.")
            candidate_id = safe_generation_id(str(marker["generation_id"]))
            remove_system_trial(sysroot)
            remove_generation_directory(identity_dir, candidate_id)
            print("discarded-failed-trial", flush=True)
            return 0
        command_line = args.cmdline.read_text(encoding="ascii")
        roothash, image_version = deployment_identity(command_line, selected_uki_path(sysroot))
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip().lower()
        generation = select_generation_for_boot(sysroot, roothash, image_version, command_line, boot_id)
        parent_usr, parent_etc = generation_parent_layers(generation, roothash, image_version)
        mount_generation(
            sysroot,
            generation,
            parent_usr_layers=parent_usr,
            parent_etc_layers=parent_etc,
        )
        print(
            f"Veyra vpkg generation mounted: {roothash} {image_version} {generation.name}",
            flush=True,
        )
        return 0
    except (OSError, UnicodeError, InitrdError) as error:
        print(f"veyra-vpkg-initrd: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
