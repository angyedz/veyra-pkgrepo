from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
import subprocess
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch


SCRIPT = Path(__file__).resolve().parents[1] / "sources/veyra-vpkg/usr/bin/vpkg"
SPEC = importlib.util.spec_from_loader("veyra_vpkg", SourceFileLoader("veyra_vpkg", str(SCRIPT)))
assert SPEC and SPEC.loader
vpkg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vpkg)


class VpkgSystemGenerationContractTests(unittest.TestCase):
    def test_system_transaction_overlay_includes_active_parent_layers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generation = root / "generation-candidate"
            parent = root / "generation-parent"
            for path in (
                generation / "upper/usr", generation / "upper/etc",
                generation / ".transaction-work/usr", generation / ".transaction-work/etc",
                parent / "upper/usr", parent / "upper/etc",
            ):
                path.mkdir(parents=True)
            with patch.object(vpkg, "run") as run:
                vpkg.mount_system_transaction_root(
                    generation,
                    (parent / "upper/usr",),
                    (parent / "upper/etc",),
                )
            self.assertEqual(run.call_args_list[0].args[0], [
                "mount", "-t", "overlay", "overlay", "-o",
                f"lowerdir={parent / 'upper/usr'}:/usr,upperdir={generation / 'upper/usr'},"
                f"workdir={generation / '.transaction-work/usr'},index=off,metacopy=off,redirect_dir=off",
                str(generation / ".transaction-root/usr"),
            ])
            self.assertEqual(run.call_args_list[1].args[0], [
                "mount", "-t", "overlay", "overlay", "-o",
                f"lowerdir={parent / 'upper/etc'}:/etc,upperdir={generation / 'upper/etc'},"
                f"workdir={generation / '.transaction-work/etc'},index=off,metacopy=off,redirect_dir=off",
                str(generation / ".transaction-root/etc"),
            ])

    def test_system_transaction_cli_requires_explicit_action_and_packages(self) -> None:
        parsed = vpkg.build_parser().parse_args(["system", "install", "htop"])
        self.assertEqual((parsed.command, parsed.system_command, parsed.packages),
                         ("system", "install", ["htop"]))
        parsed = vpkg.build_parser().parse_args(["system", "upgrade"])
        self.assertEqual(parsed.system_command, "upgrade")
        with self.assertRaises(SystemExit):
            vpkg.build_parser().parse_args(["system", "upgrade", "htop"])

    def test_system_mutation_stops_at_shared_ota_lock_before_resolution(self) -> None:
        with (
            patch.object(vpkg, "require_root"),
            patch.object(vpkg, "with_lock", side_effect=lambda action: action()),
            patch.object(vpkg, "require_no_pending_update", side_effect=vpkg.VpkgError("OTA pending")),
            patch.object(vpkg, "validate_user_package_name"),
            patch.object(vpkg, "running_deployment_roothash") as identity,
        ):
            with self.assertRaisesRegex(vpkg.VpkgError, "OTA pending"):
                vpkg.stage_system_generation("install", ["htop"])
        identity.assert_not_called()

    def test_ota_candidate_preparation_rejects_system_trial_before_solving(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_root = root / "candidate-base"
            base_root.mkdir()
            layers = root / "app-layers"
            layers.mkdir()
            output = layers / "candidate"
            with (
                patch.object(vpkg, "fedora_release_from_root", return_value="44"),
                patch.object(vpkg, "USER_APP_LAYER_DIR", layers),
                patch.object(vpkg, "load_pending_update", return_value=None),
                patch.object(vpkg, "load_staged_package_trial", return_value=None),
                patch.object(vpkg, "load_system_generation_trial", return_value={"state": "pending"}),
                patch.object(vpkg, "build_user_app_generation") as build,
            ):
                with self.assertRaisesRegex(vpkg.VpkgError, "system-generation trial"):
                    vpkg.prepare_for_base(base_root, "a" * 64, output)
            build.assert_not_called()


class VforgePackageDispatchTests(unittest.TestCase):
    def _validate(self, root: Path, marker: Path, mountinfo: Path):
        original_stat = Path.stat

        def root_owned_stat(path: Path, *args, **kwargs):
            result = original_stat(path, *args, **kwargs)
            if path == marker:
                values = list(result)
                values[4] = 0
                return os.stat_result(values)
            return result

        with patch.object(Path, "stat", autospec=True, side_effect=root_owned_stat):
            with patch.object(vpkg, "rpm_database_path", return_value=Path("/usr/lib/sysimage/rpm")):
                return vpkg.validate_container_root(root, marker, mountinfo, root / "cmdline")

    def _fixture(self, temporary: str):
        root = Path(temporary)
        (root / "usr/lib/sysimage/rpm").mkdir(parents=True)
        release = root / "usr/lib/os-release"
        release.write_text(
            'ID=fedora\nVERSION_ID=44\nIMAGE_ID=veyra-next\nIMAGE_VERSION=0.1.0\n',
            encoding="utf-8",
        )
        marker = root / "marker.json"
        marker.write_text(json.dumps({
            "schema": 1,
            "kind": "vforge-veyra-root",
            "root_id": "a" * 32,
            "image_id": "veyra-next",
            "image_version": "0.1.0",
            "base_digest": "b" * 64,
            "storage_driver": "overlayfs",
            "immutable_base": True,
        }), encoding="utf-8")
        marker.chmod(0o444)
        (root / "cmdline").write_text(f"quiet roothash={'b' * 64}\n", encoding="ascii")
        mountinfo = root / "mountinfo"
        mountinfo.write_text(f"31 1 0:1 / {marker} ro,relatime - tmpfs tmpfs ro\n", encoding="utf-8")
        return root, marker, mountinfo

    def test_vforge_uses_the_regular_package_commands(self) -> None:
        with (
            patch.object(vpkg, "is_vforge_environment", return_value=True),
            patch.object(vpkg, "validate_container_root"),
            patch.object(vpkg, "vforge_package_transaction") as transaction,
        ):
            self.assertEqual(vpkg.main(["install", "htop"]), 0)
            self.assertEqual(vpkg.main(["remove", "htop"]), 0)
            self.assertEqual(vpkg.main(["upgrade"]), 0)

        self.assertEqual(transaction.call_args_list, [
            call("install", ["htop"]),
            call("remove", ["htop"]),
            call("upgrade", None),
        ])

    def test_host_package_commands_keep_their_existing_behavior(self) -> None:
        with (
            patch.object(vpkg, "is_vforge_environment", return_value=False),
            patch.object(vpkg, "install") as install,
            patch.object(vpkg, "remove") as remove,
            patch.object(vpkg, "upgrade") as upgrade,
        ):
            self.assertEqual(vpkg.main(["install", "htop"]), 0)
            self.assertEqual(vpkg.main(["remove", "htop"]), 0)
            self.assertEqual(vpkg.main(["upgrade"]), 0)

        install.assert_called_once_with(["htop"])
        remove.assert_called_once_with(["htop"])
        upgrade.assert_called_once_with()

    def test_host_only_package_generation_commands_are_blocked_in_vforge(self) -> None:
        with (
            patch.object(vpkg, "is_vforge_environment", return_value=True),
            patch.object(vpkg, "validate_container_root"),
            patch.object(vpkg, "stage_user_apps") as stage,
        ):
            self.assertEqual(vpkg.main(["stage", "install", "htop"]), 1)

        stage.assert_not_called()

    def test_invalid_vforge_marker_never_falls_back_to_host_install(self) -> None:
        with (
            patch.object(vpkg, "is_vforge_environment", return_value=True),
            patch.object(vpkg, "validate_container_root", side_effect=vpkg.VpkgReject("invalid marker")),
            patch.object(vpkg, "install") as install,
        ):
            self.assertEqual(vpkg.main(["install", "htop"]), 1)

        install.assert_not_called()

    def test_vforge_rejects_veyra_system_extension_packages(self) -> None:
        with (
            patch.object(vpkg, "require_root"),
            patch.object(vpkg, "validate_container_root"),
            patch.object(vpkg, "with_container_lock") as lock,
        ):
            with self.assertRaisesRegex(vpkg.VpkgError, "system-extension packages"):
                vpkg.vforge_package_transaction("install", ["veyra-sample"])

        lock.assert_not_called()

    def test_vforge_marker_detection_does_not_follow_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "root.json"
            marker.symlink_to(Path(temporary) / "missing.json")
            self.assertTrue(vpkg.is_vforge_environment(marker))

    def test_vforge_marker_detection_returns_false_when_marker_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.assertFalse(vpkg.is_vforge_environment(Path(temporary) / "missing.json"))

    def test_public_cli_does_not_expose_container_subcommand(self) -> None:
        with self.assertRaises(SystemExit):
            vpkg.build_parser().parse_args(["container", "install", "htop"])

    def test_container_root_requires_private_marker_and_matching_veyra_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, marker, mountinfo = self._fixture(temporary)
            result = self._validate(root, marker, mountinfo)
            self.assertEqual(result["root_id"], "a" * 32)

    def test_container_root_rejects_fedora_host_or_overlay_mounts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, marker, mountinfo = self._fixture(temporary)
            release = root / "usr/lib/os-release"
            release.write_text("ID=fedora\nVERSION_ID=44\nIMAGE_ID=fedora\nIMAGE_VERSION=44\n", encoding="utf-8")
            with self.assertRaisesRegex(vpkg.VpkgReject, "Veyra deployment"):
                self._validate(root, marker, mountinfo)

            release.write_text(
                'ID=fedora\nVERSION_ID=44\nIMAGE_ID=veyra-next\nIMAGE_VERSION=0.1.0\n',
                encoding="utf-8",
            )
            mountinfo.write_text(
                f"31 1 0:1 / {marker} ro,relatime - tmpfs tmpfs ro\n"
                "32 1 0:2 / /usr rw,relatime - fuse.overlay fuse.overlay rw\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(vpkg.VpkgReject, "container /usr"):
                self._validate(root, marker, mountinfo)

    def test_container_marker_must_be_read_only_mount(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, marker, mountinfo = self._fixture(temporary)
            mountinfo.write_text(f"31 1 0:1 / {marker} rw,relatime - tmpfs tmpfs rw\n", encoding="utf-8")
            with self.assertRaisesRegex(vpkg.VpkgReject, "mounted read-only"):
                self._validate(root, marker, mountinfo)

    def test_container_marker_must_match_active_verity_roothash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, marker, mountinfo = self._fixture(temporary)
            (root / "cmdline").write_text(f"quiet roothash={'c' * 64}\n", encoding="ascii")
            with self.assertRaisesRegex(vpkg.VpkgReject, "active dm-verity root hash"):
                self._validate(root, marker, mountinfo)

    def test_container_session_targets_root_and_private_state(self) -> None:
        with patch.object(vpkg, "Session") as session_type:
            vpkg.container_package_session(refresh=True)
        options = session_type.call_args.kwargs
        self.assertEqual(options["installroot"], Path("/"))
        self.assertEqual(options["repo_ids"], ("fedora", "updates", *vpkg.RPMFUSION_REPOS))
        self.assertEqual(options["cache_dir"], Path("/var/cache/veyra/vpkg/container"))
        self.assertEqual(options["history_dir"], Path("/var/lib/veyra/vpkg/container/history"))
        self.assertEqual(options["persist_dir"], Path("/var/lib/veyra/vpkg/container/persist"))
        self.assertEqual(options["state_dir"], Path("/var/lib/veyra/vpkg/container/state"))
        self.assertEqual(options["log_dir"], Path("/var/lib/veyra/vpkg/container/log"))
        self.assertFalse(options["no_scripts"])

    def test_container_transaction_policy_rejects_protected_core_changes(self) -> None:
        class Change:
            name = "glibc"

        policy = {
            "schema": 1,
            "protected_packages": {"names": ["glibc"], "prefixes": ["kernel-"]},
        }
        with patch.object(vpkg, "read_json_object", return_value=policy):
            with self.assertRaisesRegex(vpkg.VpkgReject, "protected Veyra base packages"):
                vpkg.validate_container_changes((Change(),))

    def test_container_transaction_stops_before_lock_when_root_guard_fails(self) -> None:
        with (
            patch.object(vpkg, "require_root"),
            patch.object(vpkg, "validate_container_root", side_effect=vpkg.VpkgReject("invalid root")),
            patch.object(vpkg, "with_container_lock") as lock,
        ):
            with self.assertRaisesRegex(vpkg.VpkgReject, "invalid root"):
                vpkg.vforge_package_transaction("upgrade")
        lock.assert_not_called()


def running_in_qemu_vm() -> bool:
    try:
        result = subprocess.run(
            ["systemd-detect-virt", "--vm"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return False
    return result.returncode == 0 and result.stdout.strip() in {"qemu", "kvm"}


@unittest.skipUnless(running_in_qemu_vm(), "Veyra package tests run only inside QEMU/KVM")
class VpkgPolicyTests(unittest.TestCase):
    def test_generation_integrity_detects_payload_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            generation = Path(temporary) / "generation-test"
            tree = generation / "tree"
            payload = tree / "usr/bin/example"
            payload.parent.mkdir(parents=True)
            payload.write_text("original", encoding="utf-8")
            manifest = {
                "schema": 1,
                "generation_id": generation.name,
                "requests": [{"kind": "repo", "name": "example"}],
                "installed": {"example": "example-0:1-1.x86_64"},
                "integrity": {"tree_sha256": vpkg.user_app_tree_digest(tree)},
            }
            (generation / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            vpkg.verify_user_app_generation(generation)
            payload.write_text("modified", encoding="utf-8")
            with self.assertRaisesRegex(vpkg.VpkgError, "SHA-256 integrity check"):
                vpkg.verify_user_app_generation(generation)

    def test_empty_generation_records_its_parent_for_remove_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layer_dir = root / "app-layers"
            previous = layer_dir / "generation-previous"
            previous.mkdir(parents=True)
            (previous / "tree").mkdir()
            (previous / "manifest.json").write_text(
                json.dumps({"schema": 1, "requests": [], "installed": {}}),
                encoding="utf-8",
            )
            with (
                patch.object(vpkg, "USER_APP_LAYER_DIR", layer_dir),
                patch.object(vpkg, "active_user_app_generation", return_value=previous),
            ):
                generation = vpkg.create_empty_user_app_generation("a" * 64, "remove")
            manifest = vpkg.verify_user_app_generation(generation)
            self.assertEqual(manifest["parent_generation"], str(previous))
            self.assertEqual(manifest["transaction"], "remove")
            self.assertEqual(manifest["requests"], [])
            self.assertEqual(manifest["installed"], {})

    def test_rollback_selects_parent_generation_without_crossing_base_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layer_dir = root / "app-layers"
            state_dir = root / "apps"
            previous = layer_dir / "generation-previous"
            current = layer_dir / "generation-current"
            for generation in (previous, current):
                tree = generation / "tree"
                tree.mkdir(parents=True)
            previous_manifest = {
                "schema": 1,
                "generation_id": previous.name,
                "parent_generation": None,
                "requests": [],
                "installed": {},
                "base_roothash": "a" * 64,
                "integrity": {"tree_sha256": vpkg.user_app_tree_digest(previous / "tree")},
            }
            (previous / "manifest.json").write_text(json.dumps(previous_manifest), encoding="utf-8")
            current_manifest = {
                "schema": 1,
                "generation_id": current.name,
                "parent_generation": str(previous),
                "requests": [{"kind": "repo", "name": "example"}],
                "installed": {"example": "example-0:1-1.x86_64"},
                "base_roothash": "a" * 64,
                "integrity": {"tree_sha256": vpkg.user_app_tree_digest(current / "tree")},
            }
            (current / "manifest.json").write_text(json.dumps(current_manifest), encoding="utf-8")
            for generation in (previous, current):
                vpkg.seal_user_app_tree(generation / "tree")
                vpkg.seal_user_app_generation(generation)
            state_dir.mkdir()
            current_link = state_dir / "current"
            current_link.symlink_to(current, target_is_directory=True)
            with (
                patch.object(vpkg, "USER_APP_LAYER_DIR", layer_dir),
                patch.object(vpkg, "USER_APP_STATE", state_dir),
                patch.object(vpkg, "USER_APP_CURRENT", current_link),
                patch.object(vpkg, "require_root"),
                patch.object(vpkg, "with_lock", side_effect=lambda action: action()),
                patch.object(vpkg, "require_no_pending_update"),
                patch.object(vpkg, "running_deployment_roothash", return_value="a" * 64),
                patch.object(vpkg, "running_uki_version", return_value="1.0.0"),
                patch.object(vpkg, "commit_user_app_generation") as commit,
            ):
                vpkg.rollback_user_apps()
            commit.assert_called_once_with(previous, [], "a" * 64, "1.0.0")

    def test_prepare_for_empty_intents_returns_ready_without_creating_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "usr/lib").mkdir(parents=True)
            (root / "usr/lib/os-release").write_text(
                "ID=fedora\nVERSION_ID=44\n", encoding="utf-8"
            )
            layer_dir = root / "app-layers"
            layer_dir.mkdir()
            output = layer_dir / "generation-candidate"
            with (
                patch.object(vpkg, "USER_APP_LAYER_DIR", layer_dir),
                patch.object(vpkg, "load_pending_update", return_value=None),
                patch.object(vpkg, "load_user_app_intents", return_value=[]),
            ):
                result = vpkg.prepare_for_base(root, "a" * 64, output)
            self.assertEqual(result["status"], "ready")
            self.assertIsNone(result["generation"])
            self.assertFalse(output.exists())

    def test_running_uki_version_is_read_from_its_osrel_section(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            uki = Path(temporary) / "current.efi"
            image = bytearray(0x600)
            pe_offset = 0x80
            image[0:2] = b"MZ"
            struct.pack_into("<I", image, 0x3C, pe_offset)
            image[pe_offset : pe_offset + 4] = b"PE\0\0"
            struct.pack_into("<H", image, pe_offset + 6, 1)
            struct.pack_into("<H", image, pe_offset + 20, 0xF0)
            section = pe_offset + 24 + 0xF0
            image[section : section + 6] = b".osrel"
            osrel = b'ID=fedora\nIMAGE_VERSION="1.2.3-test"\n\0'
            struct.pack_into("<I", image, section + 8, len(osrel))
            struct.pack_into("<I", image, section + 16, len(osrel))
            struct.pack_into("<I", image, section + 20, 0x400)
            image[0x400 : 0x400 + len(osrel)] = osrel
            uki.write_bytes(image)
            with patch.object(
                vpkg,
                "run",
                return_value=subprocess.CompletedProcess([], 0, str(uki) + "\n", ""),
            ):
                self.assertEqual(vpkg.running_uki_version(), "1.2.3-test")

    def test_pending_completion_requires_exact_roothash_and_uki_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "pending.json"
            marker.write_text(
                json.dumps({"schema": 1, "target_roothash": "a" * 64, "version": "1.0.1"}),
                encoding="utf-8",
            )
            with (
                patch.object(vpkg, "PENDING_UPDATE_FILE", marker),
                patch.object(vpkg, "running_deployment_roothash", return_value="a" * 64),
                patch.object(vpkg, "running_uki_version", return_value="1.0.2"),
            ):
                with self.assertRaisesRegex(vpkg.VpkgError, "exact target roothash and UKI version"):
                    vpkg.complete_pending_update()
            self.assertTrue(marker.exists())
            with (
                patch.object(vpkg, "PENDING_UPDATE_FILE", marker),
                patch.object(vpkg, "running_deployment_roothash", return_value="a" * 64),
                patch.object(vpkg, "running_uki_version", return_value="1.0.1"),
            ):
                vpkg.complete_pending_update()
            self.assertFalse(marker.exists())

    def test_binding_creates_target_mapping_and_pending_lock_under_one_vpkg_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layer_dir = root / "app-layers"
            layer_dir.mkdir()
            mapping_dir = root / "deployments"
            marker = root / "pending.json"
            with (
                patch.object(vpkg, "USER_APP_LAYER_DIR", layer_dir),
                patch.object(vpkg, "DEPLOYMENT_BINDING_DIR", mapping_dir),
                patch.object(vpkg, "PENDING_UPDATE_FILE", marker),
                patch.object(vpkg, "require_root"),
                patch.object(vpkg, "with_lock", side_effect=lambda action: action()),
                patch.object(vpkg, "running_deployment_roothash", return_value="b" * 64),
                patch.object(vpkg, "running_uki_version", return_value="1.2.2"),
                patch.object(vpkg, "load_user_app_intents", return_value=[]),
            ):
                vpkg.bind_generation("b" * 64, "1.2.3", "none")
            binding = json.loads((mapping_dir / f"{'b' * 64}--1.2.3.json").read_text(encoding="utf-8"))
            pending = json.loads(marker.read_text(encoding="utf-8"))
            self.assertEqual(binding["generation"], None)
            self.assertEqual(binding["requests"], [])
            self.assertEqual(pending["target_roothash"], "b" * 64)
            self.assertEqual(pending["version"], "1.2.3")

    def test_binding_rejects_stale_candidate_before_pending_lock_is_created(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layer_dir = root / "app-layers"
            layer_dir.mkdir()
            candidate = layer_dir / "generation-candidate"
            candidate.mkdir()
            (candidate / "manifest.json").write_text(
                json.dumps({
                    "schema": 1,
                    "base_roothash": "b" * 64,
                    "requests": [{"kind": "repo", "name": "htop"}],
                    "installed": {},
                }),
                encoding="utf-8",
            )
            marker = root / "pending.json"
            with (
                patch.object(vpkg, "USER_APP_LAYER_DIR", layer_dir),
                patch.object(vpkg, "DEPLOYMENT_BINDING_DIR", root / "deployments"),
                patch.object(vpkg, "PENDING_UPDATE_FILE", marker),
                patch.object(vpkg, "require_root"),
                patch.object(vpkg, "with_lock", side_effect=lambda action: action()),
                patch.object(vpkg, "running_deployment_roothash", return_value="a" * 64),
                patch.object(vpkg, "running_uki_version", return_value="1.2.2"),
                patch.object(vpkg, "load_user_app_intents", return_value=[]),
            ):
                with self.assertRaisesRegex(vpkg.VpkgError, "intents are stale"):
                    vpkg.bind_generation("b" * 64, "1.2.3", str(candidate))
            self.assertFalse(marker.exists())
            self.assertFalse((root / "deployments" / f"{'b' * 64}--1.2.3.json").exists())

    def test_same_roothash_different_versions_selects_distinct_app_generations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layer_dir = root / "app-layers"
            layer_dir.mkdir()
            mapping_dir = root / "deployments"
            generations = []
            for version in ("1.0.0", "1.0.1"):
                generation = layer_dir / f"generation-{version}"
                generation.mkdir()
                (generation / "manifest.json").write_text(
                    json.dumps({
                        "schema": 1,
                        "base_roothash": "c" * 64,
                        "requests": [],
                        "installed": {"marker": version},
                    }),
                    encoding="utf-8",
                )
                generations.append(generation)
            with (
                patch.object(vpkg, "USER_APP_LAYER_DIR", layer_dir),
                patch.object(vpkg, "DEPLOYMENT_BINDING_DIR", mapping_dir),
                patch.object(vpkg, "USER_APP_INTENTS", root / "intents.json"),
                patch.object(vpkg, "set_user_app_current") as select_current,
                patch.object(vpkg, "sync_user_app_extension_link"),
                patch.object(vpkg, "write_user_app_intents"),
            ):
                vpkg.write_deployment_binding("c" * 64, "1.0.0", generations[0], [])
                vpkg.write_deployment_binding("c" * 64, "1.0.1", generations[1], [])
                vpkg.select_deployment_generation("c" * 64, "1.0.1")
            self.assertEqual(select_current.call_args.args[0], generations[1])
            self.assertTrue((mapping_dir / f"{'c' * 64}--1.0.0.json").is_file())
            self.assertTrue((mapping_dir / f"{'c' * 64}--1.0.1.json").is_file())

    def test_cancel_pending_requires_exact_pair_and_rejects_cancelling_running_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "pending.json"
            marker.write_text(
                json.dumps({"schema": 1, "target_roothash": "d" * 64, "version": "2.0.0"}),
                encoding="utf-8",
            )
            with patch.object(vpkg, "PENDING_UPDATE_FILE", marker):
                with self.assertRaisesRegex(vpkg.VpkgError, "does not match"):
                    vpkg.cancel_pending_update("d" * 64, "2.0.1")
                with (
                    patch.object(vpkg, "running_deployment_roothash", return_value="d" * 64),
                    patch.object(vpkg, "running_uki_version", return_value="2.0.0"),
                ):
                    with self.assertRaisesRegex(vpkg.VpkgError, "Cannot cancel"):
                        vpkg.cancel_pending_update("d" * 64, "2.0.0")
                self.assertTrue(marker.exists())
                with patch.object(vpkg, "running_deployment_roothash", return_value="e" * 64):
                    vpkg.cancel_pending_update("d" * 64, "2.0.0")
            self.assertFalse(marker.exists())

    def test_upstream_package_policy_blocks_kernel_init_boot_and_driver_packages(self) -> None:
        for name in (
            "kernel-core",
            "akmod-nvidia",
            "nvidia-driver",
            "grub2-efi-x64",
            "shim-x64",
            "systemd",
            "mesa-dri-drivers",
            "xorg-x11-drv-nouveau",
            "xorg-x11-drv-amdgpu",
            "amd-gpu-firmware",
        ):
            with self.subTest(name=name), self.assertRaises(vpkg.VpkgError):
                vpkg.validate_user_package_name(name)

    def test_upstream_package_policy_accepts_application_package_names(self) -> None:
        for name in ("nodejs", "python3-pip", "vlc", "discord"):
            with self.subTest(name=name):
                vpkg.validate_user_package_name(name)

    def test_upstream_payload_must_be_additive_usr_or_opt_content(self) -> None:
        vpkg.validate_user_package_paths([
            "/usr/bin/example",
            "/usr/share/applications/example.desktop",
            "/opt/example/bin/tool",
        ])
        for path in (
            "/usr/lib/modules/6.15.0/vmlinuz",
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/boot/efi/systemd-bootx64.efi",
            "/usr/lib64/dri/radeonsi_dri.so",
            "/usr/share/vulkan/icd.d/radeon_icd.x86_64.json",
            "/boot/efi/EFI/BOOT/BOOTX64.EFI",
            "/etc/ld.so.conf.d/example.conf",
            "/var/lib/example/state",
        ):
            with self.subTest(path=path), self.assertRaises(vpkg.VpkgError):
                vpkg.validate_user_package_paths([path])

    def test_upstream_payload_rejects_path_traversal(self) -> None:
        for path in ("usr/bin/example", "/usr/bin/../sbin/init", "/usr//bin/example"):
            with self.subTest(path=path), self.assertRaises(vpkg.VpkgError):
                vpkg.validate_user_package_paths([path])

    def test_upstream_libdnf_session_uses_fedora_sources_without_veyra(self) -> None:
        self.assertEqual(
            vpkg.selected_repo_ids("both", include_veyra=False),
            (*vpkg.FEDORA_REPOS, *vpkg.RPMFUSION_REPOS),
        )

    def test_fedora_release_is_derived_from_candidate_os_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "etc").mkdir()
            (root / "usr/lib").mkdir(parents=True)
            (root / "etc/os-release").write_text(
                'NAME="Fedora Linux"\nID=fedora\nVERSION_ID="44"\n',
                encoding="utf-8",
            )
            (root / "usr/lib/os-release").symlink_to("../../etc/os-release")

            self.assertEqual(vpkg.fedora_release_from_root(root), "44")
            with patch.object(vpkg, "Session") as session:
                vpkg.package_session(
                    Path("/tmp/installroot"),
                    base_root=root,
                    app_transaction=True,
                    include_veyra=False,
                )
            self.assertEqual(session.call_args.kwargs["releasever"], "44")

    def test_non_target_fedora_candidate_is_rejected_before_generation_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "usr/lib").mkdir(parents=True)
            (root / "usr/lib/os-release").write_text(
                f'ID=fedora\nVERSION_ID="{int(vpkg.FEDORA_RELEASE) + 1}"\n', encoding="utf-8"
            )
            layer_dir = root / "app-layers"
            layer_dir.mkdir()
            output = layer_dir / "generation-candidate"
            with (
                patch.object(vpkg, "USER_APP_LAYER_DIR", layer_dir),
                patch.object(vpkg, "load_pending_update", return_value=None),
                patch.object(vpkg, "load_user_app_intents", return_value=[]),
            ):
                with self.assertRaisesRegex(vpkg.VpkgReject, "Fedora 44"):
                    vpkg.prepare_for_base(root, "a" * 64, output)
            self.assertFalse(output.exists())

    def test_user_app_rpm_transaction_keeps_base_inventory_unchanged(self) -> None:
        base = {"bash": {"bash-0:5.2-1.x86_64"}}
        installed = {
            **base,
            "tree": {"tree-0:2.1.1-1.x86_64"},
            "gpg-pubkey": {"gpg-pubkey-123"},
        }
        with (
            patch.object(vpkg, "rpm_records", return_value=installed),
            patch.object(vpkg, "rpm_package_has_execution_hooks", return_value=False),
            patch.object(vpkg, "validate_installed_app_payloads"),
        ):
            added = vpkg.package_records_after_install(Path("/stage"), base)
        self.assertEqual(added, {"tree": "tree-0:2.1.1-1.x86_64"})

    def test_user_app_rpm_transaction_rejects_base_package_replacement(self) -> None:
        base = {"systemd": {"systemd-0:257-1.x86_64"}}
        installed = {"systemd": {"systemd-0:258-1.x86_64"}}
        with patch.object(vpkg, "rpm_records", return_value=installed):
            with self.assertRaisesRegex(vpkg.VpkgError, "REJECT: transaction changes protected base package"):
                vpkg.package_records_after_install(Path("/stage"), base)

    def test_protected_core_policy_is_machine_readable_and_fail_closed(self) -> None:
        policy_path = Path(__file__).resolve().parents[1] / "sources/veyra-vpkg/usr/share/veyra/vpkg/protected-core.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        self.assertEqual(policy["schema"], 1)
        self.assertEqual(policy["supported_base"], {"id": "fedora", "version_id": "44"})
        self.assertIn("glibc", policy["protected_packages"]["names"])
        self.assertIn("python3-libdnf5", policy["protected_packages"]["names"])
        with patch.object(vpkg, "VPKG_POLICY_FILE", policy_path):
            vpkg.load_vpkg_policy()
            with self.assertRaisesRegex(vpkg.VpkgError, "protected system path"):
                vpkg.validate_user_package_paths(["/usr/lib/modules/test.ko"])
            with self.assertRaisesRegex(vpkg.VpkgError, "protected system path"):
                vpkg.validate_user_package_paths(["/usr/share/veyra/injected.conf"])
            with self.assertRaisesRegex(vpkg.VpkgError, "base-system packages"):
                vpkg.validate_user_package_name("python3-libdnf5")
        with tempfile.TemporaryDirectory() as temporary:
            malformed = Path(temporary) / "policy.json"
            malformed.write_text('{"schema": 1}', encoding="utf-8")
            with patch.object(vpkg, "VPKG_POLICY_FILE", malformed):
                with self.assertRaisesRegex(vpkg.VpkgError, "malformed or targets an unsupported base"):
                    vpkg.load_vpkg_policy()
                with self.assertRaisesRegex(vpkg.VpkgError, "malformed or targets an unsupported base"):
                    vpkg.validate_user_package_name("example")
            missing = Path(temporary) / "missing-policy.json"
            with patch.object(vpkg, "VPKG_POLICY_FILE", missing):
                with self.assertRaisesRegex(vpkg.VpkgError, "not a regular file"):
                    vpkg.load_vpkg_policy()

    def test_user_app_transaction_classifies_safe_additions_as_live(self) -> None:
        base = {"bash": {"bash-0:5.2-1.x86_64"}}
        installed = {
            **base,
            "tree": {"tree-0:2.1.1-1.x86_64"},
            "gpg-pubkey": {"gpg-pubkey-123"},
        }
        with (
            patch.object(vpkg, "rpm_records", return_value=installed),
            patch.object(vpkg, "rpm_package_has_execution_hooks", return_value=False),
            patch.object(vpkg, "validate_installed_app_payloads"),
        ):
            classification, added, reason = vpkg.classify_user_app_transaction(Path("/stage"), base)
        self.assertEqual(classification, "LIVE")
        self.assertEqual(added, {"tree": "tree-0:2.1.1-1.x86_64"})
        self.assertIsNone(reason)

    def test_user_app_transaction_rejects_rpm_scriptlets_and_triggers(self) -> None:
        base = {"bash": {"bash-0:5.2-1.x86_64"}}
        installed = {**base, "example": {"example-1-1.x86_64"}}
        with (
            patch.object(vpkg, "rpm_records", return_value=installed),
            patch.object(vpkg, "rpm_package_has_execution_hooks", return_value=True),
            patch.object(vpkg, "validate_installed_app_payloads") as validate_payloads,
        ):
            classification, added, reason = vpkg.classify_user_app_transaction(Path("/stage"), base)
        self.assertEqual(classification, "REJECT")
        self.assertEqual(added, {})
        self.assertIn("declares RPM scriptlets, triggers, or SYSUSERS actions", reason or "")
        validate_payloads.assert_not_called()

    def test_rpm_sysusers_metadata_is_rejected_without_executing_it(self) -> None:
        outputs = ["", "", "", "absent", "u example - - /var/lib/example"]
        with patch.object(
            vpkg,
            "run",
            side_effect=[
                subprocess.CompletedProcess([], 0, output, "") for output in outputs
            ],
        ) as mocked_run:
            self.assertTrue(vpkg.rpm_package_has_execution_hooks(Path("/stage"), "example"))
        self.assertEqual(mocked_run.call_count, 5)
        self.assertIn("%{SYSUSERS}", mocked_run.call_args.args[0][-2])

    def test_rpm_hook_inspection_detects_package_triggers_without_running_them(self) -> None:
        with patch.object(
            vpkg,
            "run",
            side_effect=[
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "trigger script", ""),
            ],
        ) as mocked_run:
            self.assertTrue(vpkg.rpm_package_has_execution_hooks(Path("/stage"), "example"))
        self.assertEqual(mocked_run.call_count, 2)
        self.assertEqual(mocked_run.call_args_list[0].args[0][4], "--scripts")
        self.assertEqual(mocked_run.call_args_list[1].args[0][4], "--triggers")

    def test_user_app_transaction_rejects_unsupported_staged_replacements(self) -> None:
        base = {"python3": {"python3-0:3.13-1.x86_64"}}
        installed = {"python3": {"python3-0:3.14-1.x86_64"}}
        with patch.object(vpkg, "rpm_records", return_value=installed):
            classification, added, reason = vpkg.classify_user_app_transaction(Path("/stage"), base)
        self.assertEqual(classification, "STAGED")
        self.assertEqual(added, {})
        self.assertIn("immutable system-generation backend", reason or "")
        self.assertIn("cannot be activated by the current app-layer backend", reason or "")

    def test_app_layer_executor_does_not_activate_staged_base_replacements(self) -> None:
        base = {"python3": {"python3-0:3.13-1.x86_64"}}
        installed = {"python3": {"python3-0:3.14-1.x86_64"}}
        with patch.object(vpkg, "rpm_records", return_value=installed):
            with self.assertRaisesRegex(vpkg.VpkgError, "STAGED: transaction changes non-core base package"):
                vpkg.package_records_after_install(Path("/stage"), base)

    def test_user_app_transaction_rejects_protected_core_mutation_from_policy(self) -> None:
        base = {"glibc": {"glibc-0:2.40-1.x86_64"}}
        installed = {"glibc": {"glibc-0:2.41-1.x86_64"}}
        with patch.object(vpkg, "rpm_records", return_value=installed):
            classification, added, reason = vpkg.classify_user_app_transaction(Path("/stage"), base)
        self.assertEqual(classification, "REJECT")
        self.assertEqual(added, {})
        self.assertIn("protected base package(s) glibc", reason or "")

    def test_user_app_transaction_rejects_protected_core_removal(self) -> None:
        base = {"systemd": {"systemd-0:259-1.x86_64"}}
        with patch.object(vpkg, "rpm_records", return_value={}):
            classification, added, reason = vpkg.classify_user_app_transaction(Path("/stage"), base)
        self.assertEqual(classification, "REJECT")
        self.assertEqual(added, {})
        self.assertIn("protected base package(s) systemd", reason or "")

    def test_user_app_transaction_rejects_when_hook_metadata_cannot_be_inspected(self) -> None:
        base = {"bash": {"bash-0:5.2-1.x86_64"}}
        installed = {**base, "example": {"example-0:1-1.x86_64"}}
        with (
            patch.object(vpkg, "rpm_records", return_value=installed),
            patch.object(vpkg, "rpm_package_has_execution_hooks", side_effect=vpkg.VpkgError("rpm query failed")),
            patch.object(vpkg, "validate_installed_app_payloads") as validate_payloads,
        ):
            classification, added, reason = vpkg.classify_user_app_transaction(Path("/stage"), base)
        self.assertEqual(classification, "REJECT")
        self.assertEqual(added, {})
        self.assertIn("could not inspect RPM scripts or triggers", reason or "")
        validate_payloads.assert_not_called()

    def test_user_app_rpm_payload_policy_accepts_additive_application_files(self) -> None:
        regular = stat.S_IFREG | 0o755
        symlink = stat.S_IFLNK | 0o777
        output = (
            f"/opt/veyra-vpkg-test-31/bin/example\t{regular}\t(none)\t(none)\n"
            f"/opt/veyra-vpkg-test-31/bin/example-link\t{symlink}\t../lib/example\t(none)\n"
        )
        with patch.object(
            vpkg,
            "run",
            return_value=subprocess.CompletedProcess([], 0, output, ""),
        ):
            vpkg.validate_installed_app_payloads(Path("/stage"), {"example": "example-1"})

    def test_app_tree_allows_shared_base_directories_but_rejects_file_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            (tree / "usr/bin").mkdir(parents=True)
            (tree / "usr/bin/example").write_text("app", encoding="utf-8")
            with patch("pathlib.Path.exists", autospec=True, side_effect=lambda path: str(path) == "/usr/bin"):
                vpkg.validate_user_app_tree(tree)

            (tree / "usr/bin/bash").write_text("collision", encoding="utf-8")
            with patch("pathlib.Path.exists", autospec=True, side_effect=lambda path: str(path) in {"/usr/bin", "/usr/bin/bash"}):
                with self.assertRaisesRegex(vpkg.VpkgError, "would replace an existing base-system path"):
                    vpkg.validate_user_app_tree(tree)

    def test_user_app_rpm_payload_policy_rejects_etc_configuration(self) -> None:
        mode = stat.S_IFREG | 0o644
        output = f"/etc/ld.so.conf.d/example.conf\t{mode}\t(none)\t(none)\n"
        with patch.object(
            vpkg,
            "run",
            return_value=subprocess.CompletedProcess([], 0, output, ""),
        ):
            with self.assertRaisesRegex(vpkg.VpkgError, "outside /usr or /opt"):
                vpkg.validate_installed_app_payloads(Path("/stage"), {"example": "example-1"})

    def test_user_app_rpm_payload_policy_rejects_special_files_and_capabilities(self) -> None:
        for mode, capabilities, message in (
            (stat.S_IFIFO | 0o600, "(none)", "special app RPM file"),
            (stat.S_IFREG | 0o755, "cap_net_raw+ep", "Linux capabilities"),
        ):
            output = f"/usr/bin/example\t{mode}\t(none)\t{capabilities}\n"
            with (
                self.subTest(message=message),
                patch.object(
                    vpkg,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, output, ""),
                ),
            ):
                with self.assertRaisesRegex(vpkg.VpkgError, message):
                    vpkg.validate_installed_app_payloads(Path("/stage"), {"example": "example-1"})

    def test_app_generation_copies_only_the_candidate_tree_and_writes_manifest(self) -> None:
        base = {"bash": {"bash-0:5.2-1.x86_64"}}
        added = {**base, "tree": {"tree-0:2.1.1-1.x86_64"}}
        with tempfile.TemporaryDirectory() as temporary:
            layer_dir = Path(temporary) / "layers"

            def seed(root: Path) -> dict[str, set[str]]:
                (root / "usr/lib/sysimage/rpm").mkdir(parents=True)
                (root / "usr/lib/sysimage/rpm/Packages.db").touch()
                app_file = root / "opt/vforge-fixture/bin/example"
                app_file.parent.mkdir(parents=True)
                app_file.write_text("candidate only", encoding="utf-8")
                return base

            with (
                patch.object(vpkg, "USER_APP_LAYER_DIR", layer_dir),
                patch.object(vpkg, "active_user_app_generation", return_value=None),
                patch.object(vpkg, "seed_user_app_installroot", side_effect=seed),
                patch.object(vpkg, "rpm_records", return_value=added),
                patch.object(vpkg, "rpm_database_path", return_value=Path("/usr/lib/sysimage/rpm")),
                patch.object(vpkg, "package_session") as package_session,
                patch.object(vpkg, "extension_release_text", return_value="ID=fedora\nVERSION_ID=44\nSYSEXT_LEVEL=test\n"),
                patch.object(vpkg, "rpm_package_has_execution_hooks", return_value=False),
                patch.object(vpkg, "validate_installed_app_payloads"),
                patch.object(vpkg, "run") as run,
            ):
                package_session.return_value.resolve.return_value = None
                generation = vpkg.build_user_app_generation(
                    [{"kind": "repo", "name": "tree"}], {}
                )

            self.assertTrue((generation / "tree/opt/vforge-fixture/bin/example").is_file())
            self.assertFalse((generation / "tree/usr/lib/sysimage/rpm").exists())
            self.assertEqual(
                json.loads((generation / "manifest.json").read_text(encoding="utf-8"))["installed"],
                {"tree": "tree-0:2.1.1-1.x86_64"},
            )
            package_session.assert_called_once()

    def test_sync_app_extension_link_follows_the_persistent_generation_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layer_dir = root / "layers"
            generation = layer_dir / "generation-test"
            tree = generation / "tree"
            tree.mkdir(parents=True)
            (tree / "usr/bin").mkdir(parents=True)
            (tree / "usr/bin/example").write_text("fixture", encoding="utf-8")
            vpkg.seal_user_app_tree(tree)
            (generation / "manifest.json").write_text(
                json.dumps({
                    "schema": 1,
                    "generation_id": generation.name,
                    "requests": [{"kind": "repo", "name": "example"}],
                    "installed": {"example": "example-1"},
                    "integrity": {"tree_sha256": vpkg.user_app_tree_digest(tree)},
                }),
                encoding="utf-8",
            )
            vpkg.seal_user_app_generation(generation)
            state_dir = root / "apps"
            state_dir.mkdir()
            current = state_dir / "current"
            current.symlink_to(generation, target_is_directory=True)
            extension_link = root / "etc/extensions/vpkg-apps"
            with (
                patch.object(vpkg, "USER_APP_LAYER_DIR", layer_dir),
                patch.object(vpkg, "USER_APP_STATE", state_dir),
                patch.object(vpkg, "USER_APP_CURRENT", current),
                patch.object(vpkg, "USER_APP_SYSEXT_LINK", extension_link),
            ):
                vpkg.sync_user_app_extension_link()
                self.assertEqual(extension_link.resolve(), tree.resolve())
                vpkg.set_user_app_current(None)
                vpkg.sync_user_app_extension_link()
            self.assertFalse(extension_link.exists())
            self.assertFalse(extension_link.is_symlink())

    def test_failed_app_layer_activation_restores_previous_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            layer_dir = Path(temporary) / "layers"
            previous = layer_dir / "generation-old"
            candidate = layer_dir / "generation-new"
            previous.mkdir(parents=True)
            candidate.mkdir()
            state_dir = Path(temporary) / "apps"
            state_dir.mkdir()
            current = state_dir / "current"
            current.symlink_to(previous, target_is_directory=True)
            with (
                patch.object(vpkg, "USER_APP_LAYER_DIR", layer_dir),
                patch.object(vpkg, "USER_APP_STATE", state_dir),
                patch.object(vpkg, "USER_APP_CURRENT", current),
                patch.object(vpkg, "active_user_app_generation", return_value=previous),
                patch.object(vpkg, "sync_user_app_extension_link"),
                patch.object(
                    vpkg,
                    "run",
                    side_effect=[vpkg.VpkgError("simulated refresh failure"), subprocess.CompletedProcess([], 0)],
                ),
                patch.object(vpkg, "check_extensions_active"),
            ):
                with self.assertRaisesRegex(vpkg.VpkgError, "previous app set was restored"):
                    vpkg.activate_user_app_generation(candidate)
            self.assertEqual(current.resolve(), previous.resolve())
            self.assertFalse(candidate.exists())

    def test_boot_health_rejects_app_files_that_collide_with_a_new_base_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            generation = Path(temporary) / "generation"
            tree = generation / "tree"
            app_file = tree / "usr/bin/example-app"
            app_file.parent.mkdir(parents=True)
            app_file.write_text("application", encoding="utf-8")
            (generation / "manifest.json").write_text(
                json.dumps({"schema": 1, "requests": [], "installed": {}}),
                encoding="utf-8",
            )
            with (
                patch.object(vpkg, "active_user_app_generation", return_value=generation),
                patch.object(
                    vpkg,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        [],
                        0,
                        "/usr/bin/example-app\t33261\n/usr/bin/other-base-file\t33261\n",
                        "",
                    ),
                ),
            ):
                with self.assertRaisesRegex(vpkg.VpkgError, "conflicts with files in this base image"):
                    vpkg.check_user_app_base_conflicts()

    def test_boot_health_ignores_shared_base_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            generation = Path(temporary) / "generation"
            tree = generation / "tree"
            app_file = tree / "usr/bin/example-app"
            app_file.parent.mkdir(parents=True)
            app_file.write_text("application", encoding="utf-8")
            (generation / "manifest.json").write_text(
                json.dumps({"schema": 1, "requests": [], "installed": {}}),
                encoding="utf-8",
            )
            output = "/usr/bin\t16384\n/usr/bin/bash\t33261\n"
            with (
                patch.object(vpkg, "active_user_app_generation", return_value=generation),
                patch.object(
                    vpkg,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, output, ""),
                ),
            ):
                vpkg.check_user_app_base_conflicts()

    def test_accepts_only_exact_veyra_package_names(self) -> None:
        vpkg.validate_package_specs(["veyra-shell-tools", "veyra-codecs-1"])

    def test_rejects_fedora_names_globs_and_paths(self) -> None:
        for name in ("bash", "veyra-shell-*", "./veyra-shell-tools.rpm", "veyra-shell-tools;id"):
            with self.subTest(name=name), self.assertRaises(vpkg.VpkgError):
                vpkg.validate_package_specs([name])

    def test_default_and_saved_channels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            channel_file = Path(temporary) / "channel"
            with patch.object(vpkg, "CHANNEL_FILE", channel_file):
                self.assertEqual(vpkg.selected_channel(), "main")
                channel_file.write_text("testing\n", encoding="utf-8")
                self.assertEqual(vpkg.selected_channel(), "testing")
                channel_file.write_text("unknown\n", encoding="utf-8")
                with self.assertRaises(vpkg.VpkgError):
                    vpkg.selected_channel()

    def test_libdnf_uses_fedora_rpmfusion_and_selected_veyra_channels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            channel_file = Path(temporary) / "channel"
            channel_file.write_text("testing\n", encoding="utf-8")
            key_file = Path(temporary) / "RPM-GPG-KEY-VEYRA"
            key_file.touch()
            with (
                patch.object(vpkg, "CHANNEL_FILE", channel_file),
                patch.object(vpkg, "VPKG_PUBLIC_KEY", key_file),
            ):
                selected = vpkg.selected_repo_ids()
                self.assertEqual(
                    list(selected),
                    [
                        "fedora",
                        "updates",
                        "rpmfusion-free",
                        "rpmfusion-free-updates",
                        "rpmfusion-nonfree",
                        "rpmfusion-nonfree-updates",
                        "veyra-testing",
                    ],
                )
                both = vpkg.selected_repo_ids("both")
                self.assertEqual(both[-2:], ("veyra-main", "veyra-testing"))

    def test_fedora_queries_work_without_a_veyra_signing_key(self) -> None:
        with patch.object(vpkg, "VPKG_PUBLIC_KEY", Path("/missing/veyra-key")):
            selected = vpkg.selected_repo_ids()
        self.assertEqual(
            list(selected),
            [*vpkg.FEDORA_REPOS, *vpkg.RPMFUSION_REPOS],
        )

    def test_veyra_extension_transactions_use_only_the_selected_channel(self) -> None:
        selected = vpkg.selected_repo_ids(
            "testing",
            include_rpmfusion=False,
            include_upstream=False,
        )
        self.assertEqual(
            selected,
            ("veyra-testing",),
        )

    def test_channel_switch_uses_the_package_transaction_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            channel_file = Path(temporary) / "veyra/vpkg/channel"
            with (
                patch.object(vpkg, "require_root"),
                patch.object(vpkg, "CHANNEL_FILE", channel_file),
                patch.object(vpkg, "with_lock", side_effect=lambda action: action()) as lock,
            ):
                vpkg.set_channel("testing")

            lock.assert_called_once()
            self.assertEqual(channel_file.read_text(encoding="utf-8"), "testing\n")

    def test_install_uses_one_channel_snapshot_for_preflight_and_commit(self) -> None:
        for channel in ("main", "testing"):
            with self.subTest(channel=channel):
                with (
                    patch.object(vpkg, "require_root"),
                    patch.object(vpkg, "selected_channel", return_value=channel),
                    patch.object(vpkg, "download_for_inspection", return_value=True) as inspect,
                    patch.object(vpkg, "run_veyra_transaction") as transaction,
                    patch.object(vpkg, "with_lock", side_effect=lambda action: action()),
                ):
                    vpkg.install(["veyra-shell-tools"])

                inspect.assert_called_once_with("install", ["veyra-shell-tools"], channel=channel)
                transaction.assert_called_once_with("install", ["veyra-shell-tools"])

    def test_upgrade_transaction_uses_same_channel_as_preflight_download(self) -> None:
        for channel in ("main", "testing"):
            with self.subTest(channel=channel):
                with (
                    patch.object(vpkg, "require_root"),
                    patch.object(vpkg, "selected_channel", return_value=channel),
                    patch.object(vpkg, "download_for_inspection", return_value=True) as inspect,
                    patch.object(vpkg, "run_veyra_transaction") as transaction,
                    patch.object(vpkg, "with_lock", side_effect=lambda action: action()),
                ):
                    vpkg.upgrade()

                inspect.assert_called_once_with("upgrade", channel=channel)
                transaction.assert_called_once_with("upgrade")

    def test_upgrade_preflight_resolves_from_api_with_refresh_requested(self) -> None:
        with (
            patch.object(vpkg, "selected_channel", return_value="testing"),
            patch.object(vpkg, "package_session") as package_session,
            patch.object(vpkg, "inspect_extension_rpms", return_value=[]),
        ):
            package_session.return_value.resolve.return_value.changes = []
            self.assertFalse(vpkg.download_for_inspection("upgrade"))

        self.assertTrue(package_session.call_args.kwargs["refresh"])
        package_session.return_value.resolve.assert_called_once()

    def test_extension_rpm_policy_allows_only_var_extension_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            rpm_file = Path(temporary) / "veyra-shell-tools.rpm"
            rpm_file.touch()
            responses = [
                subprocess.CompletedProcess([], 0, "veyra-shell-tools", ""),
                subprocess.CompletedProcess(
                    [], 0, "/var\n/var/lib\n/var/lib/extensions\n/var/lib/extensions/veyra-shell-tools.raw\n", ""
                ),
                subprocess.CompletedProcess(
                    [], 0,
                    "drwxr-xr-xr-x\t/var\n"
                    "drwxr-xr-xr-x\t/var/lib\n"
                    "drwxr-xr-xr-x\t/var/lib/extensions\n"
                    "-rw-r--r--\t/var/lib/extensions/veyra-shell-tools.raw\n",
                    "",
                ),
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "absent", ""),
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "digests signatures OK", ""),
            ]
            with patch.object(vpkg, "run", side_effect=responses):
                self.assertEqual(vpkg.inspect_extension_rpms(Path(temporary)), [rpm_file])

    def test_extension_rpm_policy_rejects_symlink_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            rpm_file = Path(temporary) / "veyra-bad.rpm"
            rpm_file.touch()
            responses = [
                subprocess.CompletedProcess([], 0, "veyra-bad", ""),
                subprocess.CompletedProcess(
                    [], 0, "/var/lib/extensions/veyra-bad.raw\n", ""
                ),
                subprocess.CompletedProcess(
                    [], 0, "lrwxrwxrwx\t/var/lib/extensions/veyra-bad.raw\n", ""
                ),
            ]
            with patch.object(vpkg, "run", side_effect=responses):
                with self.assertRaisesRegex(vpkg.VpkgError, "regular, non-executable"):
                    vpkg.inspect_extension_rpms(Path(temporary))

    def test_extension_rpm_policy_rejects_system_file_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            rpm_file = Path(temporary) / "veyra-bad.rpm"
            rpm_file.touch()
            responses = [
                subprocess.CompletedProcess([], 0, "veyra-bad", ""),
                subprocess.CompletedProcess([], 0, "/usr/bin/unsafe\n", ""),
            ]
            with patch.object(vpkg, "run", side_effect=responses):
                with self.assertRaisesRegex(vpkg.VpkgError, "System files must be delivered"):
                    vpkg.inspect_extension_rpms(Path(temporary))

    def test_extension_rpm_policy_rejects_rpm_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            rpm_file = Path(temporary) / "veyra-bad.rpm"
            rpm_file.touch()
            responses = [
                subprocess.CompletedProcess([], 0, "veyra-bad", ""),
                subprocess.CompletedProcess([], 0, "/var/lib/extensions/veyra-bad.raw\n", ""),
                subprocess.CompletedProcess(
                    [], 0, "-rw-r--r--\t/var/lib/extensions/veyra-bad.raw\n", ""
                ),
                subprocess.CompletedProcess([], 0, "postinstall scriptlet", ""),
            ]
            with patch.object(vpkg, "run", side_effect=responses):
                with self.assertRaisesRegex(vpkg.VpkgError, "executable RPM scripts"):
                    vpkg.inspect_extension_rpms(Path(temporary))

    def test_extension_rpm_policy_rejects_transaction_file_triggers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            rpm_file = Path(temporary) / "veyra-bad.rpm"
            rpm_file.touch()
            responses = [
                subprocess.CompletedProcess([], 0, "veyra-bad", ""),
                subprocess.CompletedProcess([], 0, "/var/lib/extensions/veyra-bad.raw\n", ""),
                subprocess.CompletedProcess(
                    [], 0, "-rw-r--r--\t/var/lib/extensions/veyra-bad.raw\n", ""
                ),
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "present", ""),
            ]
            with patch.object(vpkg, "run", side_effect=responses):
                with self.assertRaisesRegex(vpkg.VpkgError, "transaction file triggers"):
                    vpkg.inspect_extension_rpms(Path(temporary))

    def test_sync_links_extension_from_var_installroot_and_ignores_imported_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            host_extensions = Path(temporary) / "etc-extensions"
            package_image = root / "var/lib/extensions/veyra-shell-tools.raw"
            package_image.parent.mkdir(parents=True)
            package_image.write_bytes(b"extension image")
            with (
                patch.object(vpkg, "VPKG_ROOT", root),
                patch.object(vpkg, "SYSTEM_EXTENSION_LINK_DIR", host_extensions),
                patch.object(
                    vpkg,
                    "run",
                    side_effect=[
                        subprocess.CompletedProcess([], 0, "gpg-pubkey-123\nveyra-shell-tools\n", ""),
                        subprocess.CompletedProcess(
                            [], 0,
                            "/var\n/var/lib\n/var/lib/extensions\n/var/lib/extensions/veyra-shell-tools.raw\n",
                            "",
                        ),
                    ],
                ),
            ):
                vpkg.sync_extension_links()
            link = host_extensions / "veyra-shell-tools.raw"
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.resolve(), package_image.resolve())

    def test_sync_rejects_symlinked_extension_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            host_extensions = Path(temporary) / "etc-extensions"
            package_image = root / "var/lib/extensions/veyra-shell-tools.raw"
            package_image.parent.mkdir(parents=True)
            package_image.symlink_to("/etc/passwd")
            with (
                patch.object(vpkg, "VPKG_ROOT", root),
                patch.object(vpkg, "SYSTEM_EXTENSION_LINK_DIR", host_extensions),
                patch.object(
                    vpkg,
                    "run",
                    side_effect=[
                        subprocess.CompletedProcess([], 0, "veyra-shell-tools\n", ""),
                        subprocess.CompletedProcess(
                            [], 0,
                            "/var\n/var/lib\n/var/lib/extensions\n"
                            "/var/lib/extensions/veyra-shell-tools.raw\n",
                            "",
                        ),
                    ],
                ),
            ):
                with self.assertRaisesRegex(vpkg.VpkgError, "non-empty regular file"):
                    vpkg.sync_extension_links()

    def test_sync_removes_stale_vpkg_link_after_package_removal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            host_extensions = Path(temporary) / "etc-extensions"
            host_extensions.mkdir()
            target = root / "var/lib/extensions/veyra-shell-tools.raw"
            target.parent.mkdir(parents=True)
            target.touch()
            link = host_extensions / "veyra-shell-tools.raw"
            link.symlink_to(target)
            with (
                patch.object(vpkg, "VPKG_ROOT", root),
                patch.object(vpkg, "SYSTEM_EXTENSION_LINK_DIR", host_extensions),
                patch.object(
                    vpkg,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, "", ""),
                ),
            ):
                vpkg.sync_extension_links()
            self.assertFalse(link.exists())
            self.assertFalse(link.is_symlink())

    def test_extension_health_check_requires_every_installed_extension_active(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            with (
                patch.object(vpkg, "VPKG_ROOT", root),
                patch.object(
                    vpkg,
                    "run",
                    side_effect=[
                        subprocess.CompletedProcess([], 0, "veyra-shell-tools\n", ""),
                        subprocess.CompletedProcess(
                            [], 0,
                            '[{"hierarchy":"/usr","extensions":["veyra-shell-tools"],"since":null}]',
                            "",
                        ),
                    ],
                ) as run,
            ):
                vpkg.check_extensions_active()

            self.assertEqual(run.call_count, 2)

    def test_extension_health_check_rejects_inactive_installed_extension(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            with (
                patch.object(vpkg, "VPKG_ROOT", root),
                patch.object(
                    vpkg,
                    "run",
                    side_effect=[
                        subprocess.CompletedProcess([], 0, "veyra-shell-tools\n", ""),
                        subprocess.CompletedProcess(
                            [], 0,
                            '[{"hierarchy":"/usr","extensions":[],"since":null}]',
                            "",
                        ),
                    ],
                ),
            ):
                with self.assertRaisesRegex(vpkg.VpkgError, "did not activate"):
                    vpkg.check_extensions_active()

    def test_extension_health_check_preserves_raw_suffix_in_package_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            with (
                patch.object(vpkg, "VPKG_ROOT", root),
                patch.object(
                    vpkg,
                    "run",
                    side_effect=[
                        subprocess.CompletedProcess([], 0, "veyra-example.raw\n", ""),
                        subprocess.CompletedProcess(
                            [], 0,
                            '[{"hierarchy":"/usr","extensions":["veyra-example.raw"],"since":null}]',
                            "",
                        ),
                    ],
                ),
            ):
                vpkg.check_extensions_active()


if __name__ == "__main__":
    unittest.main()
