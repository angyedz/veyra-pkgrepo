from __future__ import annotations

import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import io
import subprocess
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


MODULE = Path(__file__).resolve().parents[1] / "sources/veyra-vpkg/usr/lib/veyra/veyra_repo.py"
SPEC = importlib.util.spec_from_loader("veyra_repo", SourceFileLoader("veyra_repo", str(MODULE)))
assert SPEC and SPEC.loader
repo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repo)


class VeyraRepoTests(unittest.TestCase):
    def test_release_selection_uses_highest_semver_and_channel_flag(self) -> None:
        releases = [
            {"tag_name": "rpm-v2.0.0", "prerelease": False},
            {"tag_name": "rpm-v10.1.0", "prerelease": False},
            {"tag_name": "rpm-v99.0.0-testing", "prerelease": True},
            {"tag_name": "rpm-v3.2.1-testing", "prerelease": True},
            {"tag_name": "v100.0.0", "prerelease": False},
        ]
        with patch.object(repo, "_json_url", return_value=(releases, "")):
            self.assertEqual(repo.select_release("main")["tag_name"], "rpm-v10.1.0")
            self.assertEqual(repo.select_release("testing")["tag_name"], "rpm-v99.0.0-testing")

    def test_channel_mismatch_is_rejected(self) -> None:
        with patch.object(repo, "_json_url", return_value=([{"tag_name": "rpm-v1.0.0", "prerelease": True}], "")):
            with self.assertRaisesRegex(repo.VeyraRepoError, "No valid main release"):
                repo.select_release("main")

    def test_archive_checksum_is_strict_and_verified(self) -> None:
        archive = b"authenticated fixture"
        line = f"{hashlib.sha256(archive).hexdigest()}  {repo.ARCHIVE_NAME}\n".encode()
        self.assertEqual(repo._verify_archive_digest(archive, line), hashlib.sha256(archive).hexdigest())
        with self.assertRaisesRegex(repo.VeyraRepoError, "SHA256 check failed"):
            repo._verify_archive_digest(archive + b"x", line)
        with self.assertRaisesRegex(repo.VeyraRepoError, "invalid format"):
            repo._verify_archive_digest(archive, b"0" * 64 + b"  unrelated.tar.gz\n")

    def test_safe_extraction_accepts_regular_tree(self) -> None:
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as tar:
            for name, payload in (
                ("x86_64/repodata/repomd.xml", b"metadata"),
                ("x86_64/repodata/repomd.xml.asc", b"signature"),
                ("x86_64/RPM-GPG-KEY-VEYRA", b"key"),
                ("x86_64/pkg.rpm", b"rpm"),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "stage"
            repo._safe_extract(data.getvalue(), destination)
            self.assertEqual((destination / "x86_64/pkg.rpm").read_bytes(), b"rpm")

    def test_safe_extraction_rejects_traversal_and_links(self) -> None:
        for entry in ("x86_64/../../escape", "x86_64/link"):
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w:gz") as tar:
                info = tarfile.TarInfo(entry)
                if entry.endswith("link"):
                    info.type = tarfile.SYMTYPE
                    info.linkname = "../../escape"
                else:
                    info.size = 0
                tar.addfile(info)
            with tempfile.TemporaryDirectory() as temporary:
                destination = Path(temporary) / "stage"
                with self.assertRaises(repo.VeyraRepoError):
                    repo._safe_extract(data.getvalue(), destination)
                self.assertFalse(destination.exists())

    def test_release_asset_urls_must_be_https(self) -> None:
        release = {"assets": [{"name": repo.ARCHIVE_NAME, "browser_download_url": "http://example.test/archive"}]}
        with self.assertRaisesRegex(repo.VeyraRepoError, "non-HTTPS"):
            repo._release_asset_url(release, repo.ARCHIVE_NAME)

    def test_repomd_signature_requires_validsig_from_the_pinned_key(self) -> None:
        fingerprint = "A" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            (root / "repodata").mkdir(parents=True)
            (root / "repodata/repomd.xml").write_bytes(b"metadata")
            (root / "repodata/repomd.xml.asc").write_bytes(b"signature")
            key = Path(temporary) / "pinned-key.asc"
            key.write_bytes(b"key")
            good_calls = [
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, f"fpr:::::::::{fingerprint}:\n", ""),
                subprocess.CompletedProcess([], 0, f"[GNUPG:] VALIDSIG {fingerprint} 20261025 0 0 4 0 1 10 00\n", ""),
            ]
            with patch.object(repo.subprocess, "run", side_effect=good_calls):
                repo.verify_repomd_signature(root, key)
            bad_calls = [
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, f"fpr:::::::::{fingerprint}:\n", ""),
                subprocess.CompletedProcess([], 0, f"[GNUPG:] VALIDSIG {'B' * 40} 20261025 0 0 4 0 1 10 00\n", ""),
            ]
            with patch.object(repo.subprocess, "run", side_effect=bad_calls):
                with self.assertRaisesRegex(repo.VeyraRepoError, "invalid or not pinned"):
                    repo.verify_repomd_signature(root, key)


if __name__ == "__main__":
    unittest.main()
