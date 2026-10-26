from __future__ import annotations

import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "sources/veyra-vforge/usr/bin/vforge"
SPEC = importlib.util.spec_from_loader("veyra_vforge", SourceFileLoader("veyra_vforge", str(SCRIPT)))
assert SPEC and SPEC.loader
vforge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vforge)
CURRENT_BASE_IDENTITY = vforge.current_base_identity


class VforgeNativeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = patch.dict(os.environ, {
            "XDG_DATA_HOME": str(self.root / "data"),
            "XDG_CONFIG_HOME": str(self.root / "config"),
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.base_identity = {
            "image_id": "veyra-next",
            "image_version": "0.1.0",
            "base_digest": "a" * 64,
        }
        self.base_patch = patch.object(vforge, "current_base_identity", return_value=self.base_identity)
        self.base_patch.start()
        self.addCleanup(self.base_patch.stop)
    def test_named_environment_persists_overlay_upper_and_work_directories(self) -> None:
        path = vforge.create("backend")

        metadata = json.loads((path / "environment.json").read_text())
        self.assertEqual(metadata["backend"], "overlayfs")
        self.assertEqual(metadata["lower"], "/")
        self.assertTrue(Path(metadata["upper"]).is_dir())
        self.assertTrue(Path(metadata["work"]).is_dir())
        self.assertEqual(vforge.environment_metadata(path), metadata)

    def test_home_permission_metadata_migration_preserves_environment_identity(self) -> None:
        path = vforge.create("backend")
        metadata_path = path / "environment.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["root_id"] = "c" * 32
        metadata.pop("home_mode")
        metadata_path.write_text(json.dumps(metadata))

        migrated = vforge.environment_metadata(path)

        self.assertEqual(migrated["schema"], 2)
        self.assertEqual(migrated["home_mode"], "none")
        self.assertEqual(migrated["root_id"], "c" * 32)

    def test_namespace_entry_binds_to_the_current_veyra_base_and_rejects_changed_base(self) -> None:
        path = vforge.create("backend")
        original = {"image_id": "veyra-next", "image_version": "0.1.0", "base_digest": "a" * 64}
        changed = {"image_id": "veyra-next", "image_version": "0.2.0", "base_digest": "b" * 64}
        with (
            patch.object(vforge, "current_base_identity", return_value=original),
            patch.object(vforge.subprocess, "run", return_value=type("Result", (), {"returncode": 0})()) as run,
        ):
            self.assertEqual(vforge.namespace_command(path, ["/bin/true"]), 0)
        self.assertEqual(vforge.environment_metadata(path)["base_identity"], original)

        with (
            patch.object(vforge, "current_base_identity", return_value=changed),
            patch.object(vforge.subprocess, "run") as run,
        ):
            with self.assertRaisesRegex(vforge.VforgeError, "base changed"):
                vforge.namespace_command(path, ["/bin/true"])
        run.assert_not_called()

    def test_current_base_identity_requires_an_immutable_veyra_root(self) -> None:
        marker = {
            "image_id": "veyra-next",
            "image_version": "0.1.0",
            "base_digest": "a" * 64,
        }
        with (
            patch.object(vforge, "verify_immutable_root_mount") as verify,
            patch.object(vforge, "veyra_root_marker", return_value=marker),
        ):
            identity = CURRENT_BASE_IDENTITY({"root_id": "b" * 32})

        verify.assert_called_once()
        self.assertEqual(identity, marker)

    def test_snapshot_restores_overlay_upper_and_is_bound_to_environment_and_base(self) -> None:
        path = vforge.create("backend")
        base = {"image_id": "veyra-next", "image_version": "0.1.0", "base_digest": "a" * 64}
        state_file = path / "upper/etc/vforge-fixture"
        state_file.parent.mkdir(parents=True)
        state_file.write_text("before snapshot")

        with patch.object(vforge, "current_base_identity", return_value=base):
            snapshot_id = vforge.snapshot_environment(path)
            state_file.write_text("after snapshot")
            vforge.rollback_environment(path, snapshot_id)

        self.assertEqual(state_file.read_text(), "before snapshot")
        saved = vforge.read_snapshot(path, snapshot_id)
        self.assertEqual(saved["base_identity"], base)
        self.assertEqual(saved["root_id"], vforge.environment_metadata(path)["root_id"])

    def test_snapshot_refuses_to_run_while_environment_has_an_active_session(self) -> None:
        path = vforge.create("backend")
        base = {"image_id": "veyra-next", "image_version": "0.1.0", "base_digest": "a" * 64}
        with (
            patch.object(vforge, "current_base_identity", return_value=base),
            vforge.environment_lock(path),
        ):
            with self.assertRaisesRegex(vforge.VforgeError, "active sessions"):
                vforge.snapshot_environment(path)

    def test_vforge_upgrade_rebases_base_and_restores_snapshot_if_package_upgrade_fails(self) -> None:
        path = vforge.create("backend")
        old = {"image_id": "veyra-next", "image_version": "0.1.0", "base_digest": "a" * 64}
        new = {"image_id": "veyra-next", "image_version": "0.2.0", "base_digest": "b" * 64}
        metadata = vforge.environment_metadata(path)
        metadata["base_identity"] = old
        vforge.write_metadata(path, metadata)
        state_file = path / "upper/etc/vforge-fixture"
        state_file.parent.mkdir(parents=True)
        state_file.write_text("before upgrade")

        with (
            patch.object(vforge, "current_base_identity", return_value=new),
            patch.object(vforge, "namespace_command", return_value=0) as command,
        ):
            snapshot_id = vforge.upgrade_environment(path)
        self.assertEqual(vforge.environment_metadata(path)["base_identity"], new)
        self.assertEqual(command.call_args.args, (path, ["vpkg", "upgrade"]))
        self.assertEqual(vforge.read_snapshot(path, snapshot_id)["base_identity"], old)

        def fail_after_partial_update(*args, **kwargs) -> int:
            (path / "upper/etc/vforge-fixture").write_text("partially upgraded")
            return 1

        with (
            patch.object(vforge, "current_base_identity", return_value=new),
            patch.object(vforge, "namespace_command", side_effect=fail_after_partial_update),
        ):
            with self.assertRaisesRegex(vforge.VforgeError, "previous snapshot was restored"):
                vforge.upgrade_environment(path)
        self.assertEqual((path / "upper/etc/vforge-fixture").read_text(), "before upgrade")
        self.assertEqual(vforge.environment_metadata(path)["base_identity"], new)

    def test_snapshot_commands_support_named_and_current_project_environments(self) -> None:
        parsed = vforge.build_parser().parse_args(["snapshot", "backend"])
        self.assertEqual((parsed.action, parsed.name), ("snapshot", "backend"))
        parsed = vforge.build_parser().parse_args(["rollback", "--snapshot", "1234567890-abcdef12"])
        self.assertEqual((parsed.action, parsed.name, parsed.snapshot_id), ("rollback", None, "1234567890-abcdef12"))

        project = self.root / "source"
        project.mkdir()
        (project / ".vforge.toml").write_text('[environment]\nname = "backend"\n')
        self.assertEqual(vforge.environment_target(None, project), project / ".vforge" / "backend")

    def test_project_environment_stays_in_project_vforge_directory(self) -> None:
        project = self.root / "source"
        project.mkdir()
        (project / "main.py").write_text("print('hello')")

        path = vforge.create("backend", project=project)

        self.assertEqual(path, project / ".vforge" / "backend")
        metadata = vforge.environment_metadata(path)
        self.assertEqual(metadata["project"], str(project))
        self.assertTrue((project / "main.py").is_file())

    def test_project_mounts_are_explicit_and_read_only_by_default(self) -> None:
        shared = self.root / "shared"
        shared.mkdir()

        mounts = vforge.normalize_mounts([{"source": str(shared), "target": "/workspace/shared"}])

        self.assertEqual(mounts, [{"source": str(shared), "target": "/workspace/shared", "access": "read-only"}])

    def test_rejects_mount_targets_that_can_replace_system_paths_or_escape_root(self) -> None:
        for target in ("/", "/usr/local", "/etc", "/../host", "relative/path"):
            with self.subTest(target=target), self.assertRaises(vforge.VforgeError):
                vforge.checked_mount_target(target)

    def test_rejects_symlink_mount_sources(self) -> None:
        real = self.root / "real"
        real.mkdir()
        link = self.root / "link"
        link.symlink_to(real, target_is_directory=True)

        with self.assertRaisesRegex(vforge.VforgeError, "mount source"):
            vforge.normalize_mounts([{"source": str(link), "target": "/workspace/shared"}])

    def test_project_configuration_must_not_be_a_symlink(self) -> None:
        project = self.root / "source"
        project.mkdir()
        config = self.root / "external-config.toml"
        config.write_text('[environment]\nname = "backend"\n')
        (project / ".vforge.toml").symlink_to(config)

        with self.assertRaisesRegex(vforge.VforgeError, "configuration may not be a symlink"):
            vforge.project_settings(project)

    def test_project_network_is_isolated_unless_shared_is_requested(self) -> None:
        project = self.root / "source"
        project.mkdir()
        self.assertEqual(vforge.project_settings(project), ("source", [], "isolated", "project-only", []))

        (project / ".vforge.toml").write_text(
            '[environment]\nname = "backend"\n[permissions]\nnetwork = "shared"\n'
        )
        self.assertEqual(vforge.project_settings(project), ("backend", [], "shared", "project-only", []))

    def test_project_package_requests_are_validated(self) -> None:
        project = self.root / "source"
        project.mkdir()
        config = project / ".vforge.toml"
        config.write_text(
            '[packages]\nsystem = ["python3", "nodejs", "git"]\n',
            encoding="utf-8",
        )

        self.assertEqual(vforge.project_settings(project), ("source", [], "isolated", "project-only", ["python3", "nodejs", "git"]))

        config.write_text('[packages]\nsystem = ["--installroot=/"]\n', encoding="utf-8")
        with self.assertRaisesRegex(vforge.VforgeError, "package name"):
            vforge.project_settings(project)

    def test_vforge_package_commands_route_through_vpkg_inside_selected_environment(self) -> None:
        path = vforge.create("backend")
        with patch.object(vforge, "namespace_command", return_value=0) as command:
            result = vforge.package_command("install", ["htop"], self.root, environment_name="backend")

        self.assertEqual(result, 0)
        command.assert_called_once_with(path, ["vpkg", "install", "htop"])

    def test_vforge_package_commands_default_to_current_project(self) -> None:
        project = self.root / "source"
        project.mkdir()
        (project / ".vforge.toml").write_text('[environment]\nname = "backend"\n')
        project_environment = vforge.create("backend", project=project)

        with patch.object(vforge, "namespace_command", return_value=0) as command:
            vforge.package_command("remove", ["htop"], project)

        command.assert_called_once_with(project_environment, ["vpkg", "remove", "htop"])

    def test_vforge_package_cli_accepts_environment_option(self) -> None:
        parsed = vforge.build_parser().parse_args(["install", "htop", "--environment", "backend"])
        self.assertEqual((parsed.action, parsed.environment, parsed.packages), ("install", "backend", ["htop"]))

    def test_project_up_installs_declared_packages_inside_the_environment(self) -> None:
        project = self.root / "source"
        project.mkdir()
        (project / ".vforge.toml").write_text(
            '[environment]\nname = "backend"\n[packages]\nsystem = ["python3", "git"]\n',
            encoding="utf-8",
        )

        with patch.object(vforge, "namespace_command", return_value=0) as command:
            path = vforge.project_up(project)

        command.assert_called_once_with(path, ["vpkg", "install", "python3", "git"])

    def test_project_up_reports_package_install_failure(self) -> None:
        project = self.root / "source"
        project.mkdir()
        (project / ".vforge.toml").write_text(
            '[packages]\nsystem = ["python3"]\n',
            encoding="utf-8",
        )

        with patch.object(vforge, "namespace_command", return_value=1):
            with self.assertRaisesRegex(vforge.VforgeError, "project packages"):
                vforge.project_up(project)

    def test_project_rejects_unknown_network_permission(self) -> None:
        project = self.root / "source"
        project.mkdir()
        (project / ".vforge.toml").write_text('[permissions]\nnetwork = "host"\n')

        with self.assertRaisesRegex(vforge.VforgeError, "network must be isolated or shared"):
            vforge.project_settings(project)

    def test_project_home_modes_are_parsed_and_invalid_modes_are_rejected(self) -> None:
        project = self.root / "source"
        project.mkdir()
        config = project / ".vforge.toml"
        for mode in ("none", "project-only", "read-only", "read-write"):
            config.write_text(f'[permissions.home]\nmode = "{mode}"\n', encoding="utf-8")
            self.assertEqual(vforge.project_settings(project)[3], mode)

        config.write_text('[permissions.home]\nmode = "everything"\n', encoding="utf-8")
        with self.assertRaisesRegex(vforge.VforgeError, "permissions.home.mode"):
            vforge.project_settings(project)

    def test_host_home_permissions_require_and_store_explicit_approval(self) -> None:
        project = self.root / "source"
        project.mkdir()
        with patch.object(vforge, "confirm_home_permission") as confirm:
            path = vforge.create("backend", project=project, home_mode="read-only")

        confirm.assert_called_once_with("backend", "read-only")
        self.assertEqual(vforge.environment_metadata(path)["home_mode"], "read-only")
        self.assertEqual(vforge.project_home_approval(project), "read-only")

        with patch.object(vforge, "confirm_home_permission") as confirm:
            vforge.create("backend", project=project, home_mode="read-write")

        confirm.assert_called_once_with("backend", "read-write")
        self.assertEqual(vforge.project_home_approval(project), "read-write")

    def test_host_home_permission_fails_closed_without_interactive_approval(self) -> None:
        project = self.root / "source"
        project.mkdir()
        with (
            patch.object(vforge.sys.stdin, "isatty", return_value=False),
            self.assertRaisesRegex(vforge.VforgeError, "requires interactive approval"),
        ):
            vforge.create("backend", project=project, home_mode="read-write")

        self.assertFalse((project / ".vforge" / "backend").exists())

    def test_revoked_host_home_permission_stops_environment_entry(self) -> None:
        project = self.root / "source"
        project.mkdir()
        (project / ".vforge.toml").write_text(
            '[permissions.home]\nmode = "read-only"\n', encoding="utf-8"
        )
        with patch.object(vforge, "confirm_home_permission"):
            path = vforge.create("backend", project=project, home_mode="read-only")
        approvals = json.loads((vforge.config_directory() / vforge.PERMISSION_FILE).read_text())
        approvals["home_projects"].pop(str(project))
        (vforge.config_directory() / vforge.PERMISSION_FILE).write_text(json.dumps(approvals))

        with patch.object(vforge.subprocess, "run") as run:
            with self.assertRaisesRegex(vforge.VforgeError, "Home permission is not approved"):
                vforge.namespace_command(path, ["/bin/true"])

        run.assert_not_called()

    def test_home_mode_change_stops_environment_until_project_up(self) -> None:
        project = self.root / "source"
        project.mkdir()
        config = project / ".vforge.toml"
        config.write_text('[permissions.home]\nmode = "read-only"\n', encoding="utf-8")
        with patch.object(vforge, "confirm_home_permission"):
            path = vforge.create("backend", project=project, home_mode="read-only")
        config.write_text('[permissions.home]\nmode = "project-only"\n', encoding="utf-8")

        with patch.object(vforge.subprocess, "run") as run:
            with self.assertRaisesRegex(vforge.VforgeError, "permissions changed"):
                vforge.namespace_command(path, ["/bin/true"])

        run.assert_not_called()

    def test_shared_project_network_requires_recorded_user_approval(self) -> None:
        project = self.root / "source"
        project.mkdir()
        (project / ".vforge.toml").write_text(
            '[environment]\nname = "backend"\n[permissions]\nnetwork = "shared"\n'
        )

        with patch.object(vforge, "confirm_network_permission") as confirm:
            path = vforge.create("backend", project=project, network="shared")

        confirm.assert_called_once_with("backend")
        self.assertEqual(vforge.environment_metadata(path)["network"], "shared")
        self.assertEqual(vforge.project_network_approval(project), "shared")

        with patch.object(vforge.subprocess, "run", return_value=type("Result", (), {"returncode": 0})()) as run:
            self.assertEqual(vforge.namespace_command(path, ["/bin/true"]), 0)
        self.assertNotIn("--net", run.call_args.args[0])

    def test_shared_project_network_fails_closed_without_interactive_approval(self) -> None:
        project = self.root / "source"
        project.mkdir()
        (project / ".vforge.toml").write_text(
            '[environment]\nname = "backend"\n[permissions]\nnetwork = "shared"\n'
        )

        with patch.object(vforge.sys.stdin, "isatty", return_value=False):
            with self.assertRaisesRegex(vforge.VforgeError, "requires interactive approval"):
                vforge.create("backend", project=project, network="shared")

        self.assertFalse((project / ".vforge" / "backend").exists())

    def test_project_network_isolation_remains_active_without_sharing(self) -> None:
        project = self.root / "source"
        project.mkdir()
        path = vforge.create("backend", project=project)
        with patch.object(vforge.subprocess, "run", return_value=type("Result", (), {"returncode": 0})()) as run:
            self.assertEqual(vforge.namespace_command(path, ["/bin/true"]), 0)

        self.assertIn("--net", run.call_args.args[0])

    def test_shared_network_environment_refuses_revoked_approval(self) -> None:
        project = self.root / "source"
        project.mkdir()
        (project / ".vforge.toml").write_text(
            '[environment]\nname = "backend"\n[permissions]\nnetwork = "shared"\n'
        )
        with patch.object(vforge, "confirm_network_permission"):
            path = vforge.create("backend", project=project, network="shared")
        approval_path = vforge.config_directory() / vforge.PERMISSION_FILE
        approvals = json.loads(approval_path.read_text())
        approvals["network_projects"].pop(str(project))
        approval_path.write_text(json.dumps(approvals))

        with patch.object(vforge.subprocess, "run") as run:
            with self.assertRaisesRegex(vforge.VforgeError, "shared network permission is not approved"):
                vforge.namespace_command(path, ["/bin/true"])

        run.assert_not_called()

    def test_shared_network_stops_when_project_configuration_is_changed(self) -> None:
        project = self.root / "source"
        project.mkdir()
        config = project / ".vforge.toml"
        config.write_text('[environment]\nname = "backend"\n[permissions]\nnetwork = "shared"\n')
        with patch.object(vforge, "confirm_network_permission"):
            path = vforge.create("backend", project=project, network="shared")
        config.write_text('[environment]\nname = "backend"\n[permissions]\nnetwork = "isolated"\n')

        with patch.object(vforge.subprocess, "run") as run:
            with self.assertRaisesRegex(vforge.VforgeError, "permissions changed"):
                vforge.namespace_command(path, ["/bin/true"])

        run.assert_not_called()

    def test_root_base_must_be_read_only_erofs(self) -> None:
        mountinfo = "40 30 0:1 / / ro,relatime - erofs /dev/mapper/veyra-root ro\n"
        vforge.verify_immutable_root_mount(mountinfo)
        with self.assertRaisesRegex(vforge.VforgeError, "EROFS root"):
            vforge.verify_immutable_root_mount(
                "40 30 0:1 / / rw,relatime - overlay overlay rw\n"
            )

    def test_unmount_inherited_submounts_before_using_veyra_root_as_lower(self) -> None:
        lower = Path("/run/veyra-vforge/lower")
        mountinfo = (
            "40 30 0:1 / /run/veyra-vforge/lower ro,relatime - erofs /dev/root ro\n"
            "41 40 0:2 / /run/veyra-vforge/lower/var ro,relatime - ext4 /dev/var ro\n"
            "42 41 0:3 / /run/veyra-vforge/lower/var/lib rw,relatime - ext4 /dev/state rw\n"
            "43 40 0:4 / /run/veyra-vforge/lower/home/Shared\\040Data rw,relatime - ext4 /dev/home rw\n"
        )
        mountpoints = [str(lower)]

        with patch.object(vforge, "run") as run:
            vforge.unmount_inherited_submounts(lower, mountpoints, mountinfo)

        self.assertEqual(
            [call.args[0][-1] for call in run.call_args_list],
            [
                str(lower / "var/lib"),
                str(lower / "home/Shared Data"),
                str(lower / "var"),
            ],
        )
        self.assertEqual(mountpoints, [str(lower)])

    def test_unmount_inherited_submounts_skips_a_mount_already_detached(self) -> None:
        lower = Path("/run/veyra-vforge/lower")
        mountinfo = (
            "40 30 0:1 / /run/veyra-vforge/lower ro,relatime - erofs /dev/root ro\n"
            "41 40 0:2 / /run/veyra-vforge/lower/sys ro,relatime - sysfs sysfs ro\n"
            "42 41 0:3 / /run/veyra-vforge/lower/sys/fs/fuse/connections rw,relatime - fusectl fusectl rw\n"
        )
        current_mountinfo = "40 30 0:1 / /run/veyra-vforge/lower ro,relatime - erofs /dev/root ro\n"
        mountpoints = [str(lower)]

        with (
            patch.object(vforge, "run", side_effect=[vforge.VforgeError("not mounted"), None]) as run,
            patch.object(Path, "read_text", return_value=current_mountinfo),
        ):
            vforge.unmount_inherited_submounts(lower, mountpoints, mountinfo)

        self.assertEqual(
            [call.args[0][-1] for call in run.call_args_list],
            [str(lower / "sys/fs/fuse/connections"), str(lower / "sys")],
        )
        self.assertEqual(mountpoints, [str(lower)])

    def test_unmount_inherited_submounts_keeps_failing_if_mount_is_still_present(self) -> None:
        lower = Path("/run/veyra-vforge/lower")
        mountinfo = (
            "40 30 0:1 / /run/veyra-vforge/lower ro,relatime - erofs /dev/root ro\n"
            "41 40 0:2 / /run/veyra-vforge/lower/sys ro,relatime - sysfs sysfs ro\n"
        )
        mountpoints = [str(lower)]

        with (
            patch.object(vforge, "run", side_effect=vforge.VforgeError("device busy")),
            patch.object(Path, "read_text", return_value=mountinfo),
        ):
            with self.assertRaisesRegex(vforge.VforgeError, "device busy"):
                vforge.unmount_inherited_submounts(lower, mountpoints, mountinfo)

        self.assertEqual(mountpoints, [str(lower), str(lower / "sys")])

    def test_vforge_marker_identifies_active_veyra_root_and_overlay(self) -> None:
        root = self.root / "root"
        (root / "usr/lib").mkdir(parents=True)
        (root / "usr/lib/os-release").write_text(
            'ID=fedora\nVERSION_ID=44\nIMAGE_ID=veyra-next\nIMAGE_VERSION="0.1.0"\n',
            encoding="utf-8",
        )
        cmdline = self.root / "cmdline"
        roothash = "b" * 64
        cmdline.write_text(f"quiet roothash={roothash} boot=veyra\n", encoding="ascii")

        marker = vforge.veyra_root_marker({"root_id": "a" * 32}, root, cmdline)

        self.assertEqual(marker["root_id"], "a" * 32)
        self.assertEqual(marker["base_digest"], roothash)
        self.assertEqual(marker["storage_driver"], "overlayfs")

    def test_vpkg_state_is_created_inside_private_overlay_root(self) -> None:
        root = self.root / "root"
        (root / "usr/lib/sysimage/rpm").mkdir(parents=True)
        vforge.ensure_vpkg_state(root)

        self.assertTrue((root / "usr/lib/sysimage/rpm").is_dir())
        self.assertTrue((root / "var/lib/veyra/vpkg/container/history").is_dir())
        self.assertTrue((root / "var/cache/veyra/vpkg/container").is_dir())

    def test_invalid_environment_metadata_fails_closed(self) -> None:
        path = self.root / "legacy"
        path.mkdir()
        path.chmod(0o700)
        metadata = path / "environment.json"
        metadata.write_text('{"schema": 1, "backend": "unknown"}')
        metadata.chmod(0o600)

        with self.assertRaisesRegex(vforge.VforgeError, "unsupported Vforge backend"):
            vforge.environment_metadata(path)

    def test_namespace_command_selects_user_mount_pid_and_network_namespaces(self) -> None:
        path = vforge.create("backend")
        with patch.object(vforge.subprocess, "run", return_value=type("Result", (), {"returncode": 0})()) as run:
            self.assertEqual(vforge.namespace_command(path, ["/bin/true"]), 0)

        command = run.call_args.args[0]
        self.assertIn("--user", command)
        self.assertIn("--mount", command)
        self.assertIn("--pid", command)
        self.assertIn("--net", command)

    def test_named_environment_shared_network_requires_confirmation(self) -> None:
        with patch.object(vforge, "confirm_network_permission") as confirm:
            path = vforge.create("backend", network="shared")

        confirm.assert_called_once_with("backend")
        with patch.object(vforge.subprocess, "run", return_value=type("Result", (), {"returncode": 0})()) as run:
            self.assertEqual(vforge.namespace_command(path, ["/bin/true"]), 0)
        self.assertNotIn("--net", run.call_args.args[0])

        parsed = vforge.build_parser().parse_args(["create", "toolbox", "--network", "shared"])
        self.assertEqual(parsed.network, "shared")

    def test_named_environment_home_access_requires_explicit_confirmation(self) -> None:
        with patch.object(vforge, "confirm_home_permission") as confirm:
            path = vforge.create("backend", home_mode="read-write")

        confirm.assert_called_once_with("backend", "read-write")
        self.assertEqual(vforge.environment_metadata(path)["home_mode"], "read-write")
        parsed = vforge.build_parser().parse_args(["create", "toolbox", "--home", "read-only"])
        self.assertEqual(parsed.home_mode, "read-only")
        with self.assertRaisesRegex(vforge.VforgeError, "project-only Home mode"):
            vforge.create("project-only", home_mode="project-only")

    def test_environment_unmounts_private_mounts_before_removing_runtime_tree(self) -> None:
        environment = vforge.create("backend")
        runtime = self.root / "runtime"
        runtime.mkdir(mode=0o700)
        mounted: list[str] = []
        commands: list[list[str]] = []

        def fake_run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
            commands.append(command)
            if command[0] == "mount" and command[1] != "--make-rprivate" and command[1] != "-o":
                mounted.append(command[-1])
            return subprocess.CompletedProcess(command, 0, "", "")

        def fake_bind_mount(source: str, target: str, *, readonly: bool = False, mountpoints=None) -> None:
            mounted.append(target)
            if mountpoints is not None:
                mountpoints.append(target)

        with (
            patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(runtime)}),
            patch.object(vforge, "verify_immutable_root_mount"),
            patch.object(vforge, "veyra_root_marker", return_value={}),
            patch.object(vforge, "run", side_effect=fake_run),
            patch.object(vforge, "mount_in_namespace", side_effect=fake_bind_mount),
            patch.object(vforge.os, "fork", return_value=12345),
            patch.object(vforge.os, "waitpid", return_value=(12345, 0)),
        ):
            self.assertEqual(vforge.run_environment(environment, ["/bin/true"]), 0)

        unmounted = [command[-1] for command in commands if command[0] == "umount"]
        self.assertEqual(unmounted, list(reversed(mounted)), f"mounted={mounted!r}")
        self.assertEqual(
            [command[:3] for command in commands if command[:2] == ["mount", "--rbind"]],
            [["mount", "--rbind", "/"]],
        )
        lower_remounts = [
            command for command in commands
            if command[:3] == ["mount", "-o", "remount,bind,ro"]
            and command[-1].endswith("/lower")
        ]
        self.assertEqual(lower_remounts, [])
        self.assertEqual(list((runtime / "vforge").iterdir()), [])

    def test_read_only_home_is_bound_read_only_inside_environment(self) -> None:
        project = self.root / "source"
        project.mkdir()
        (project / ".vforge.toml").write_text(
            '[environment]\nname = "backend"\n[permissions.home]\nmode = "read-only"\n',
            encoding="utf-8",
        )
        with patch.object(vforge, "confirm_home_permission"):
            environment = vforge.create("backend", project=project, home_mode="read-only")
        host_home = self.root / "host-home"
        host_home.mkdir(mode=0o700)
        runtime = self.root / "runtime"
        runtime.mkdir(mode=0o700)
        mounts: list[tuple[str, str, bool]] = []

        def fake_run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
            return subprocess.CompletedProcess(command, 0, "", "")

        def fake_bind_mount(source: str, target: str, *, readonly: bool = False, mountpoints=None) -> None:
            mounts.append((source, target, readonly))
            if mountpoints is not None:
                mountpoints.append(target)

        with (
            patch.dict(os.environ, {
                "XDG_RUNTIME_DIR": str(runtime),
                vforge.HOST_HOME_NAME_ENV: "fixture-user",
                vforge.HOST_HOME_PATH_ENV: str(host_home),
            }),
            patch.object(vforge, "verify_immutable_root_mount"),
            patch.object(vforge, "veyra_root_marker", return_value={}),
            patch.object(vforge, "run", side_effect=fake_run),
            patch.object(vforge, "mount_in_namespace", side_effect=fake_bind_mount),
            patch.object(vforge.os, "fork", return_value=12345),
            patch.object(vforge.os, "waitpid", return_value=(12345, 0)),
        ):
            self.assertEqual(vforge.run_environment(environment, ["/bin/true"]), 0)

        self.assertIn((str(host_home), mounts_target := next(
            target for source, target, _ in mounts if source == str(host_home)
        ), True), mounts)
        self.assertTrue(mounts_target.endswith("/home/fixture-user"))

    def test_bind_mount_pins_regular_files_and_rejects_symlinks(self) -> None:
        source = self.root / "device"
        source.write_text("device fixture")
        target = self.root / "target"
        target.touch()
        mountpoints: list[str] = []
        with patch.object(vforge, "run") as run:
            vforge.mount_in_namespace(str(source), str(target), mountpoints=mountpoints)

        self.assertEqual(mountpoints, [str(target)])
        self.assertEqual(run.call_args.args[0][1], "--bind")
        self.assertTrue(run.call_args.args[0][2].startswith("/proc/self/fd/"))

        link = self.root / "device-link"
        link.symlink_to(source)
        with self.assertRaisesRegex(vforge.VforgeError, "symlink"):
            vforge.mount_in_namespace(str(link), str(target))

    def test_storage_root_can_be_selected_and_reused(self) -> None:
        selected = self.root / "persistent-vforge"
        vforge.main(["create", "--storage-root", str(selected), "backend"])

        self.assertEqual(vforge.store_root(), selected)
        self.assertTrue((selected / "environments" / "backend" / "upper").is_dir())


if __name__ == "__main__":
    unittest.main()
