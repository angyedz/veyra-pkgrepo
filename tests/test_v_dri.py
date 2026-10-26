from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "sources/veyra-v-dri/usr/bin/v-dri"
SPEC = importlib.util.spec_from_loader("veyra_vdri", SourceFileLoader("veyra_vdri", str(SCRIPT)))
assert SPEC and SPEC.loader
vdri = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vdri)


class VdriStatusTests(unittest.TestCase):
    def make_device(self, root: Path, *, taint: str = "", driver: str | None = "virtio_gpu") -> None:
        signature_parameter = root / "module/module/parameters/sig_enforce"
        signature_parameter.parent.mkdir(parents=True)
        signature_parameter.write_text("Y\n", encoding="ascii")
        device = root / "devices/pci0000:00/0000:00:02.0"
        device.mkdir(parents=True)
        (device / "vendor").write_text("0x1af4\n", encoding="ascii")
        (device / "device").write_text("0x1050\n", encoding="ascii")
        (device / "class").write_text("0x030000\n", encoding="ascii")
        card = root / "class/drm/card0"
        card.mkdir(parents=True)
        (card / "device").symlink_to("../../../devices/pci0000:00/0000:00:02.0")
        if driver is not None:
            driver_path = root / "bus/pci/drivers" / driver
            driver_path.mkdir(parents=True)
            module_path = root / "module" / driver
            module_path.mkdir(parents=True)
            (module_path / "taint").write_text(taint, encoding="ascii")
            (driver_path / "module").symlink_to(module_path)
            (device / "driver").symlink_to(driver_path)

    def test_reports_bound_kernel_driver_and_hardware_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_device(root)

            result = vdri.collect_status(root, kernel="6.15.0-veyra")

        self.assertEqual(result["schema"], 2)
        self.assertEqual(result["kernel"], "6.15.0-veyra")
        self.assertEqual(result["driver_policy"], "fedora-in-tree-only")
        self.assertEqual(result["module_signature_enforcement"], "enforced")
        self.assertEqual(result["devices"], [{
            "name": "card0",
            "vendor_id": "1af4",
            "device_id": "1050",
            "driver": "virtio_gpu",
            "module": "virtio_gpu",
            "module_taint": "",
            "status": "bound",
        }])

    def test_marks_externally_tainted_driver_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_device(root, taint="O")

            result = vdri.collect_status(root)

        self.assertEqual(result["devices"][0]["status"], "external-module-detected")

    def test_reports_permissive_module_signature_policy_as_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_device(root)
            (root / "module/module/parameters/sig_enforce").write_text("N\n", encoding="ascii")

            result = vdri.collect_status(root)

        self.assertEqual(result["module_signature_enforcement"], "permissive")
        self.assertTrue(vdri._has_problem(result))

    def test_reports_unavailable_module_signature_state_as_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_device(root)
            (root / "module/module/parameters/sig_enforce").unlink()

            result = vdri.collect_status(root)

        self.assertEqual(result["module_signature_enforcement"], "unavailable")
        self.assertTrue(vdri._has_problem(result))

    def test_marks_device_without_bound_driver_unbound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_device(root, driver=None)

            result = vdri.collect_status(root)

        self.assertEqual(result["devices"][0]["status"], "unbound")
        self.assertIsNone(result["devices"][0]["module"])

    def test_ignores_drm_connector_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_device(root)
            (root / "class/drm/card0-DP-1").mkdir()
            (root / "class/drm/renderD128").mkdir()

            result = vdri.collect_status(root)

        self.assertEqual([item["name"] for item in result["devices"]], ["card0"])

    def test_reports_no_graphics_devices(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "class/drm").mkdir(parents=True)
            result = vdri.collect_status(root, kernel="6.15.0-veyra")

        self.assertEqual(result, {
            "schema": 2,
            "kernel": "6.15.0-veyra",
            "driver_policy": "fedora-in-tree-only",
            "module_signature_enforcement": "unavailable",
            "devices": [],
        })

    def test_rejects_device_symlink_escape_from_sysfs_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "sys"
            root.mkdir()
            outside = Path(temporary) / "outside-device"
            outside.mkdir()
            card = root / "class/drm/card0"
            card.mkdir(parents=True)
            (card / "device").symlink_to(outside)

            with self.assertRaisesRegex(vdri.VdriError, "escapes the sysfs root"):
                vdri.collect_status(root)

    def test_cli_json_status_reports_problem_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_device(root, taint="O")
            output = []
            with patch.object(vdri, "SYSFS_ROOT", root), patch("sys.stdout.write", side_effect=output.append):
                result = vdri.main(["status", "--json"])

        self.assertEqual(result, 2)
        self.assertEqual(json.loads("".join(output))["devices"][0]["status"], "external-module-detected")


if __name__ == "__main__":
    unittest.main()
