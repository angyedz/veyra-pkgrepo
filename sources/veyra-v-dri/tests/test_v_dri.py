import importlib.util
from importlib.machinery import SourceFileLoader
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).parents[1] / "usr/bin/v-dri"
LOADER = SourceFileLoader("veyra_v_dri", str(SCRIPT))
SPEC = importlib.util.spec_from_loader("veyra_v_dri", LOADER)
v_dri = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(v_dri)


class VeyraDriverInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.device = self.root / "sys/bus/pci/devices/0000:00:02.0"
        self.device.mkdir(parents=True)
        (self.device / "class").write_text("0x030000\n")
        (self.device / "vendor").write_text("0x8086\n")
        (self.device / "device").write_text("0x1234\n")
        (self.device / "subsystem_vendor").write_text("0x8086\n")
        (self.device / "subsystem_device").write_text("0x5678\n")
        (self.device / "modalias").write_text("pci:v00008086d00001234sv00008086sd00005678bc03sc00i00\n")
        (self.root / "proc/sys/kernel").mkdir(parents=True)
        (self.root / "proc/sys/kernel/osrelease").write_text("6.14.0-veyra.fc44.x86_64\n")
        (self.root / "proc").mkdir(exist_ok=True)
        (self.root / "proc/cmdline").write_text("root=/dev/vda3 ro\n")

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def query(args):
        if args[:3] == ["modprobe", "--resolve-alias", "pci:"]:
            return "i915\n", None
        if args[:2] == ["modprobe", "--resolve-alias"]:
            return "i915\n", None
        if args[:2] == ["modinfo", "-F"]:
            field = args[2]
            values = {
                "filename": "/usr/lib/modules/6.14.0-veyra.fc44.x86_64/kernel/drivers/gpu/drm/i915/i915.ko.xz",
                "vermagic": "6.14.0-veyra.fc44.x86_64 SMP preempt mod_unload",
                "signer": "Fedora kernel signing key",
            }
            return values[field], None
        return None, "unexpected command"

    def test_reports_bound_device_and_compatible_candidate(self):
        (self.root / "sys/bus/pci/drivers/i915").mkdir(parents=True)
        (self.device / "driver").symlink_to(self.root / "sys/bus/pci/drivers/i915")
        with patch.object(v_dri, "command_output", side_effect=self.query):
            report = v_dri.collect_inventory(self.root)
        self.assertEqual(report["kernel_release"], "6.14.0-veyra.fc44.x86_64")
        self.assertEqual(report["devices"][0]["driver"], "i915")
        self.assertEqual(report["devices"][0]["candidates"][0]["name"], "i915")
        self.assertTrue(report["devices"][0]["candidates"][0]["kernel_compatible"])
        self.assertEqual(report["devices"][0]["issues"], [])

    def test_missing_driver_binding_is_reported_without_mutation(self):
        with patch.object(v_dri, "command_output", side_effect=self.query):
            report = v_dri.collect_inventory(self.root)
        self.assertIsNone(report["devices"][0]["driver"])
        self.assertIn(v_dri.ISSUE_MISSING_BINDING, report["devices"][0]["issues"])

    def test_mismatched_vermagic_is_reported(self):
        def mismatched(args):
            output, error = self.query(args)
            if args[:2] == ["modinfo", "-F"] and args[2] == "vermagic":
                return "6.13.0-wrong SMP", None
            return output, error

        with patch.object(v_dri, "command_output", side_effect=mismatched):
            report = v_dri.collect_inventory(self.root)
        self.assertIn(v_dri.ISSUE_KERNEL_MISMATCH, report["devices"][0]["issues"])

    def test_secure_boot_variable_and_signature_enforcement_are_read_only(self):
        efi = self.root / "sys/firmware/efi/efivars"
        efi.mkdir(parents=True)
        (efi / "SecureBoot-1234").write_bytes(b"\x07\x00\x00\x00\x01")
        module_params = self.root / "sys/module/module/parameters"
        module_params.mkdir(parents=True)
        (module_params / "sig_enforce").write_text("Y\n")
        self.assertTrue(v_dri.efi_secure_boot_state(self.root / "sys"))
        self.assertEqual(v_dri.signature_enforcement(self.root / "sys", self.root / "proc"), "enforced")


if __name__ == "__main__":
    unittest.main()
