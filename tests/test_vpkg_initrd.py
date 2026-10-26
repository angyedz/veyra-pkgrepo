from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import call, patch


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "sources/veyra-vpkg/usr/libexec/veyra-vpkg-initrd.py"
SPEC = importlib.util.spec_from_loader(
    "veyra_vpkg_initrd", SourceFileLoader("veyra_vpkg_initrd", str(HELPER))
)
assert SPEC and SPEC.loader
initrd = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(initrd)


class VpkgInitrdGenerationTests(unittest.TestCase):
    @staticmethod
    def make_uki(path: Path, os_release: bytes) -> None:
        sections = {b".osrel": (os_release, 0x200)}
        image = bytearray(0x500)
        pe_offset = 0x80
        image[:2] = b"MZ"
        struct.pack_into("<I", image, 0x3C, pe_offset)
        image[pe_offset : pe_offset + 4] = b"PE\0\0"
        struct.pack_into("<H", image, pe_offset + 6, len(sections))
        struct.pack_into("<H", image, pe_offset + 20, 0xF0)
        section_table = pe_offset + 24 + 0xF0
        for index, (name, (content, raw_offset)) in enumerate(sections.items()):
            header = section_table + index * 40
            image[header : header + len(name)] = name
            struct.pack_into("<I", image, header + 8, len(content))
            struct.pack_into("<I", image, header + 16, 0x100)
            struct.pack_into("<I", image, header + 20, raw_offset)
            image[raw_offset : raw_offset + len(content)] = content
        path.write_bytes(image)

    def test_identity_uses_roothash_and_uki_osrel_image_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            uki = Path(temporary) / "boot.efi"
            self.make_uki(uki, b'ID=fedora\nVERSION_ID=44\nIMAGE_VERSION="0.1.7-test"\n')
            identity = initrd.deployment_identity(
                "quiet roothash=" + "a" * 64 + " systemd.unit=graphical.target", uki
            )
        self.assertEqual(identity, ("a" * 64, "0.1.7-test"))

    def test_identity_rejects_missing_duplicate_or_unsupported_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            uki = Path(temporary) / "boot.efi"
            self.make_uki(uki, b'ID=fedora\nVERSION_ID=44\nIMAGE_VERSION="0.1.7"\n')
            for command_line in (
                "quiet",
                "roothash=" + "a" * 64 + " roothash=" + "b" * 64,
                "roothash=invalid",
            ):
                with self.subTest(command_line=command_line), self.assertRaises(initrd.InitrdError):
                    initrd.deployment_identity(command_line, uki)
            self.make_uki(uki, b'ID=fedora\nVERSION_ID=46\nIMAGE_VERSION="0.1.7"\n')
            with self.assertRaisesRegex(initrd.InitrdError, "Fedora 44"):
                initrd.deployment_identity("roothash=" + "a" * 64, uki)

    def test_bootstrap_creates_a_generation_owned_rpm_database_and_active_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary) / "sysroot"
            rpmdb = sysroot / "usr/lib/sysimage/rpm"
            rpmdb.mkdir(parents=True)
            (rpmdb / "Packages.db").write_bytes(b"base rpm db")
            (sysroot / "etc").mkdir()
            (sysroot / "var").mkdir()

            generation = initrd.ensure_base_generation(sysroot, "a" * 64, "0.1.7")

            self.assertEqual(
                (generation / "upper/usr/lib/sysimage/rpm/Packages.db").read_bytes(),
                b"base rpm db",
            )
            self.assertEqual((rpmdb / "Packages.db").read_bytes(), b"base rpm db")
            self.assertEqual(
                (generation / "manifest.json").read_text(encoding="utf-8"),
                json.dumps(
                    json.loads((generation / "manifest.json").read_text(encoding="utf-8")),
                    sort_keys=True,
                    separators=(",", ":"),
                ) + "\n",
            )
            self.assertEqual((generation.parent / "active").resolve(), generation)
            self.assertTrue((generation / "upper/etc").is_dir())
            self.assertTrue((generation / "work/usr").is_dir())
            self.assertTrue((generation / "work/etc").is_dir())

    def test_bootstrap_fails_closed_for_symlinked_base_rpm_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary) / "sysroot"
            (sysroot / "usr/lib/sysimage").mkdir(parents=True)
            (sysroot / "var/lib/rpm").mkdir(parents=True)
            (sysroot / "usr/lib/sysimage/rpm").symlink_to("/var/lib/rpm")
            with self.assertRaisesRegex(initrd.InitrdError, "RPM database"):
                initrd.ensure_base_generation(sysroot, "a" * 64, "0.1.7")

    def test_bootstrap_rejects_symlinked_state_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sysroot = root / "sysroot"
            rpmdb = sysroot / "usr/lib/sysimage/rpm"
            rpmdb.mkdir(parents=True)
            (rpmdb / "Packages.db").write_bytes(b"base rpm db")
            (sysroot / "etc").mkdir()
            (sysroot / "var").mkdir()
            outside = root / "untrusted-state"
            outside.mkdir()
            (sysroot / "var/lib").mkdir()
            (sysroot / "var/lib/veyra").symlink_to(outside)

            with self.assertRaisesRegex(initrd.InitrdError, "symlink"):
                initrd.ensure_base_generation(sysroot, "a" * 64, "0.1.7")

    def test_trial_selection_does_not_change_active_until_complete_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary) / "sysroot"
            rpmdb = sysroot / "usr/lib/sysimage/rpm"
            rpmdb.mkdir(parents=True)
            (rpmdb / "Packages.db").write_bytes(b"base rpm db")
            (sysroot / "etc").mkdir()
            (sysroot / "var").mkdir()
            parent = initrd.ensure_base_generation(sysroot, "a" * 64, "0.1.7")

            trial = initrd.create_trial_generation(sysroot, "a" * 64, "0.1.7")
            manifest = json.loads((trial / "manifest.json").read_text(encoding="utf-8"))
            usr_layers, etc_layers = initrd.generation_parent_layers(trial, "a" * 64, "0.1.7")
            self.assertEqual(manifest["parent_generation"], parent.name)
            self.assertEqual(list((trial / "upper/usr").iterdir()), [trial / "upper/usr/lib"])
            self.assertEqual(usr_layers, (parent / "upper/usr",))
            self.assertEqual(etc_layers, (parent / "upper/etc",))
            origin_boot = "11111111-1111-4111-8111-111111111111"
            trial_boot = "22222222-2222-4222-8222-222222222222"
            initrd.write_system_trial(sysroot, {
                "schema": 1,
                "kind": "system-generation",
                "roothash": "a" * 64,
                "version": "0.1.7",
                "generation_id": trial.name,
                "parent_generation": parent.name,
                "origin_boot_id": origin_boot,
                "attempts": 0,
                "state": "pending",
            })
            selected_before_reboot = initrd.select_generation_for_boot(
                sysroot, "a" * 64, "0.1.7", f"roothash={'a' * 64}", origin_boot
            )
            self.assertEqual(selected_before_reboot, parent)
            selected = initrd.select_generation_for_boot(
                sysroot, "a" * 64, "0.1.7", f"roothash={'a' * 64}", trial_boot
            )
            self.assertEqual(selected, trial)
            self.assertEqual((parent.parent / "active").resolve(), parent)
            self.assertEqual(initrd.read_system_trial(sysroot)["attempts"], 1)

            initrd.complete_system_trial(sysroot, "a" * 64, "0.1.7", trial_boot)
            self.assertEqual((parent.parent / "active").resolve(), trial)
            self.assertIsNone(initrd.read_system_trial(sysroot))
            rolled_back = initrd.rollback_generation(sysroot, "a" * 64, "0.1.7")
            self.assertEqual(rolled_back, parent)
            self.assertEqual((parent.parent / "active").resolve(), parent)

    def test_unhealthy_trial_falls_back_to_active_generation_on_next_boot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary) / "sysroot"
            rpmdb = sysroot / "usr/lib/sysimage/rpm"
            rpmdb.mkdir(parents=True)
            (rpmdb / "Packages.db").write_bytes(b"base rpm db")
            (sysroot / "etc").mkdir()
            (sysroot / "var").mkdir()
            parent = initrd.ensure_base_generation(sysroot, "a" * 64, "0.1.7")
            trial = initrd.create_trial_generation(sysroot, "a" * 64, "0.1.7")
            initrd.write_system_trial(sysroot, {
                "schema": 1,
                "kind": "system-generation",
                "roothash": "a" * 64,
                "version": "0.1.7",
                "generation_id": trial.name,
                "parent_generation": parent.name,
                "origin_boot_id": "11111111-1111-4111-8111-111111111111",
                "attempts": 0,
                "state": "pending",
            })

            first_boot = initrd.select_generation_for_boot(
                sysroot, "a" * 64, "0.1.7", "roothash=" + "a" * 64,
                "22222222-2222-4222-8222-222222222222",
            )
            fallback = initrd.select_generation_for_boot(
                sysroot, "a" * 64, "0.1.7", "roothash=" + "a" * 64,
                "33333333-3333-4333-8333-333333333333",
            )

            self.assertEqual(first_boot, trial)
            self.assertEqual(fallback, parent)
            self.assertEqual((parent.parent / "active").resolve(), parent)
            self.assertEqual(initrd.read_system_trial(sysroot)["state"], "failed")

    def test_foreign_or_corrupt_trial_is_rejected_without_changing_active(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary) / "sysroot"
            rpmdb = sysroot / "usr/lib/sysimage/rpm"
            rpmdb.mkdir(parents=True)
            (rpmdb / "Packages.db").write_bytes(b"base rpm db")
            (sysroot / "etc").mkdir()
            (sysroot / "var").mkdir()
            parent = initrd.ensure_base_generation(sysroot, "a" * 64, "0.1.7")
            trial = initrd.create_trial_generation(sysroot, "a" * 64, "0.1.7")

            with self.assertRaisesRegex(initrd.InitrdError, "different deployment identity"):
                initrd.read_generation(trial.parent, trial.name, "b" * 64, "0.1.7")
            self.assertEqual((parent.parent / "active").resolve(), parent)

            initrd.write_system_trial(sysroot, {
                "schema": 1,
                "kind": "system-generation",
                "roothash": "a" * 64,
                "version": "0.1.7",
                "generation_id": trial.name,
                "parent_generation": parent.name,
                "origin_boot_id": "11111111-1111-4111-8111-111111111111",
                "attempts": 0,
                "state": "pending",
            })
            (trial / "upper/usr/lib/sysimage/rpm/Packages.db").write_bytes(b"corrupted")
            selected = initrd.select_generation_for_boot(
                sysroot,
                "a" * 64,
                "0.1.7",
                "roothash=" + "a" * 64,
                "22222222-2222-4222-8222-222222222222",
            )
            self.assertEqual(selected, parent)
            self.assertEqual((parent.parent / "active").resolve(), parent)
            self.assertEqual(initrd.read_system_trial(sysroot)["state"], "failed")

    def test_active_usr_upper_digest_detects_payload_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary) / "sysroot"
            rpmdb = sysroot / "usr/lib/sysimage/rpm"
            rpmdb.mkdir(parents=True)
            (rpmdb / "Packages.db").write_bytes(b"base rpm db")
            (sysroot / "etc").mkdir()
            (sysroot / "var").mkdir()
            generation = initrd.ensure_base_generation(sysroot, "a" * 64, "0.1.7")
            payload = generation / "upper/usr/bin/example"
            payload.parent.mkdir(parents=True)
            payload.write_text("tampered", encoding="utf-8")

            with self.assertRaisesRegex(initrd.InitrdError, "/usr upper failed its integrity check"):
                initrd.read_active_generation(generation.parent, "a" * 64, "0.1.7")

    def test_unbooted_trial_can_be_cancelled_without_changing_active_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary) / "sysroot"
            rpmdb = sysroot / "usr/lib/sysimage/rpm"
            rpmdb.mkdir(parents=True)
            (rpmdb / "Packages.db").write_bytes(b"base rpm db")
            (sysroot / "etc").mkdir()
            (sysroot / "var").mkdir()
            parent = initrd.ensure_base_generation(sysroot, "a" * 64, "0.1.7")
            trial = initrd.create_trial_generation(sysroot, "a" * 64, "0.1.7")
            boot_id = "11111111-1111-4111-8111-111111111111"
            initrd.write_system_trial(sysroot, {
                "schema": 1, "kind": "system-generation", "roothash": "a" * 64,
                "version": "0.1.7", "generation_id": trial.name,
                "parent_generation": parent.name, "origin_boot_id": boot_id,
                "attempts": 0, "state": "pending",
            })

            initrd.cancel_unbooted_trial(sysroot, "a" * 64, "0.1.7", boot_id)

            self.assertEqual((parent.parent / "active").resolve(), parent)
            self.assertFalse(trial.exists())
            self.assertIsNone(initrd.read_system_trial(sysroot))

    def test_mounts_generation_owned_usr_and_etc_uppers_before_switch_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary) / "sysroot"
            generation = sysroot / "var/lib/veyra/vpkg/system-generations/id/generation-1"
            for relative in (
                "upper/usr", "upper/etc", "work/usr", "work/etc",
                "usr", "etc",
            ):
                (generation / relative if relative.startswith(("upper", "work")) else sysroot / relative).mkdir(
                    parents=True, exist_ok=True
                )
            parent = sysroot / "var/lib/veyra/vpkg/system-generations/id/generation-parent"
            parent_usr = parent / "upper/usr"
            parent_etc = parent / "upper/etc"
            parent_usr.mkdir(parents=True)
            parent_etc.mkdir(parents=True)
            with patch.object(initrd.subprocess, "run") as run:
                initrd.mount_generation(
                    sysroot,
                    generation,
                    parent_usr_layers=(parent_usr,),
                    parent_etc_layers=(parent_etc,),
                )

            self.assertEqual(run.call_args_list, [
                call(
                    ["mount", "-t", "overlay", "overlay", "-o",
                     f"lowerdir={parent_usr}:{sysroot}/usr,upperdir={generation}/upper/usr,workdir={generation}/work/usr,"
                     "index=off,metacopy=off,redirect_dir=off,ro",
                     str(sysroot / "usr")],
                    check=True,
                ),
                call(
                    ["mount", "-t", "overlay", "overlay", "-o",
                     f"lowerdir={parent_etc}:{sysroot}/etc,upperdir={generation}/upper/etc,workdir={generation}/work/etc,"
                     "index=off,metacopy=off,redirect_dir=off",
                     str(sysroot / "etc")],
                    check=True,
                ),
            ])

    def test_selected_uki_is_resolved_under_the_mounted_efi_system_partition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            uki = root / "efi/EFI/Linux/veyra-next_0.1.7.efi"
            uki.parent.mkdir(parents=True)
            uki.write_bytes(b"UKI")
            with patch.object(
                initrd.subprocess, "run", return_value=type("Result", (), {"stdout": "/EFI/Linux/veyra-next_0.1.7.efi\n"})()
            ) as run:
                selected = initrd.selected_uki_path(root / "sysroot", efi_roots=(root / "efi",))

            self.assertEqual(selected, uki)
            run.assert_called_once_with(
                ["bootctl", "--print-stub-path"], check=True, text=True,
                stdout=initrd.subprocess.PIPE, stderr=initrd.subprocess.PIPE,
            )

    def test_selected_uki_rejects_paths_outside_mounted_esp_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "tmp/not-the-esp.efi"
            outside.parent.mkdir()
            outside.write_bytes(b"UKI")
            with patch.object(
                initrd.subprocess, "run", return_value=type("Result", (), {"stdout": str(outside)})()
            ), self.assertRaisesRegex(initrd.InitrdError, "mounted EFI System Partition"):
                initrd.selected_uki_path(root / "sysroot", efi_roots=(root / "efi",))

    def test_trial_generation_keeps_parent_layer_without_copying_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary) / "sysroot"
            rpmdb = sysroot / "usr/lib/sysimage/rpm"
            rpmdb.mkdir(parents=True)
            (rpmdb / "Packages.db").write_bytes(b"base rpm db")
            (sysroot / "etc").mkdir()
            (sysroot / "var").mkdir()
            parent = initrd.ensure_base_generation(sysroot, "a" * 64, "0.1.7")

            trial = initrd.create_trial_generation(sysroot, "a" * 64, "0.1.7")

            self.assertEqual(list((trial / "upper/usr").iterdir()), [trial / "upper/usr/lib"])


if __name__ == "__main__":
    unittest.main()
