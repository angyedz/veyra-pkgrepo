"""Package parsing and command validation for Veyra AppCenter.

This module deliberately has no Qt dependency so it can be tested in CI.
"""
import json
import re

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@-]{0,127}$")
FLATPAK_ID_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$")
APK_VERSION_RE = re.compile(r"^(?P<name>.+)-(?P<version>[0-9][A-Za-z0-9._+~:-]*)-r[0-9]+$")
FLATHUB_URL = "https://dl.flathub.org/repo/flathub.flatpakrepo"


def validate_name(value):
    if not isinstance(value, str) or not NAME_RE.fullmatch(value):
        raise ValueError("Invalid package name")
    return value


def parse_apk_search(output):
    packages = []
    seen = set()
    for line in output.splitlines():
        artifact, marker, description = line.partition(" - ")
        match = APK_VERSION_RE.fullmatch(artifact.strip())
        if not marker or match is None:
            continue
        name = match.group("name")
        if name in seen or not NAME_RE.fullmatch(name):
            continue
        seen.add(name)
        packages.append({
            "name": name, "version": match.group("version"),
            "description": description.strip(), "source": "apk",
            "removeKey": "", "installed": False,
        })
        if len(packages) >= 250:
            break
    return packages


def parse_apk_installed(output):
    packages = []
    for name in output.splitlines():
        name = name.strip()
        if NAME_RE.fullmatch(name):
            packages.append({
                "name": name, "version": "", "description": "Installed APK package",
                "source": "apk", "removeKey": "", "installed": True,
            })
    return packages[:5000]


def validate_flatpak_id(value):
    if not isinstance(value, str) or not FLATPAK_ID_RE.fullmatch(value):
        raise ValueError("Invalid Flatpak application ID")
    return value


def parse_flatpak_list(output, installed=False):
    """Parse Flatpak's application/name/description column output safely."""
    packages = []
    seen = set()
    for line in output.splitlines():
        fields = [part.strip() for part in line.split("\t")]
        if len(fields) == 1:
            fields = line.strip().split(None, 1)
        if not fields:
            continue
        app_id = fields[0]
        if not FLATPAK_ID_RE.fullmatch(app_id) or app_id in seen:
            continue
        seen.add(app_id)
        title = fields[1] if len(fields) > 1 and fields[1] else app_id
        description = fields[2] if len(fields) > 2 else ""
        packages.append({
            "name": app_id, "title": title, "version": "",
            "description": description, "source": "flatpak",
            "removeKey": "", "installed": installed,
        })
        if len(packages) >= 250:
            break
    return packages


def parse_nix_search(output):
    data = json.loads(output)
    if not isinstance(data, dict):
        raise ValueError("Unexpected Nix search format")
    packages = []
    for attr, metadata in data.items():
        if not isinstance(attr, str) or not isinstance(metadata, dict):
            continue
        name = attr.rsplit(".", 1)[-1]
        if not NAME_RE.fullmatch(name):
            continue
        packages.append({
            "name": name, "version": str(metadata.get("version", "")),
            "description": str(metadata.get("description", "")),
            "source": "nix", "removeKey": "", "installed": False,
        })
        if len(packages) >= 250:
            break
    return packages


def parse_nix_profile(output):
    data = json.loads(output)
    elements = data.get("elements", {}) if isinstance(data, dict) else {}
    if not isinstance(elements, (dict, list)):
        raise ValueError("Unexpected Nix profile format")
    packages = []
    entries = elements.items() if isinstance(elements, dict) else enumerate(elements)
    for index, info in entries:
        if not isinstance(info, dict):
            continue
        # Newer Nix stores elements by index, older versions by manifest name.
        path = str(info.get("attrPath") or info.get("originalUrl") or "")
        name = path.rsplit("#", 1)[-1].rsplit(".", 1)[-1]
        if not NAME_RE.fullmatch(name):
            name = str(info.get("pname") or "")
        if not NAME_RE.fullmatch(name):
            continue
        remove_key = str(index)
        if not remove_key.isdecimal():
            # Unsupported profile schema: don't offer a destructive action.
            remove_key = ""
        packages.append({
            "name": name, "version": str(info.get("version") or ""),
            "description": "Installed Nix profile package",
            "source": "nix", "removeKey": remove_key, "installed": True,
        })
    return packages


def nix_cli(*parts):
    # Explicit opt-in to the Nix 2.x CLI; no implicit system-wide mutations.
    return ["nix", "--extra-experimental-features", "nix-command flakes", *parts]

# Curated launch page: familiar end-user applications, no developer/game packages.
# Names are validated against Alpine Stable in GitHub Actions.
FEATURED_APPS = (
    ("firefox", "Firefox", "Private and flexible web browser", "Internet"),
    ("chromium", "Chromium", "Fast open-source web browser", "Internet"),
    ("thunderbird", "Thunderbird", "Email, calendar and contacts", "Internet"),
    ("libreoffice", "LibreOffice", "Documents, presentations and spreadsheets", "Office"),
    ("evince", "Document Viewer", "Read PDF and document files", "Office"),
    ("vlc", "VLC", "Video and audio player", "Media"),
    ("mpv", "mpv", "Minimalist high-performance media player", "Media"),
    ("audacity", "Audacity", "Record and edit audio", "Media"),
    ("gimp", "GIMP", "Edit photos and images", "Creative"),
    ("inkscape", "Inkscape", "Draw vector graphics", "Creative"),
    ("krita", "Krita", "Digital drawing and painting", "Creative"),
    ("keepassxc", "KeePassXC", "Store passwords locally and securely", "Utilities"),
    ("filezilla", "FileZilla", "Transfer files over SFTP and FTP", "Utilities"),
    ("transmission-gtk", "Transmission", "A simple BitTorrent client", "Utilities"),
)

FLATPAK_FEATURED_APPS = (
    ("com.discordapp.Discord", "Discord", "Discord desktop client from Flathub", "Internet"),
    ("org.telegram.desktop", "Telegram Desktop", "Telegram messaging app", "Internet"),
    ("org.videolan.VLC", "VLC", "Video and audio player", "Media"),
    ("org.gimp.GIMP", "GIMP", "Edit photos and images", "Creative"),
)


def featured_packages(category="All"):
    if category not in ("All", "Internet", "Office", "Media", "Creative", "Utilities"):
        raise ValueError("Unknown category")
    return [
        {
            "name": name, "title": title, "version": "",
            "description": description, "category": section,
            "source": "apk", "removeKey": "", "installed": False
        }
        for name, title, description, section in FEATURED_APPS
        if category == "All" or category == section
    ]


def featured_flatpak_packages(category="All"):
    if category not in ("All", "Internet", "Office", "Media", "Creative", "Utilities"):
        raise ValueError("Unknown category")
    return [
        {
            "name": app_id, "title": title, "version": "Flathub",
            "description": description, "category": section,
            "source": "flatpak", "removeKey": "", "installed": False,
        }
        for app_id, title, description, section in FLATPAK_FEATURED_APPS
        if category == "All" or category == section
    ]

