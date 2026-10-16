"""Tests for application store parsing — no graphical display required."""
import importlib.util
import json
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "src/veyra-appcenter/backend.py"
spec = importlib.util.spec_from_file_location("veyra_backend", PATH)
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


class PackageParsing(unittest.TestCase):
    def test_apk_search(self):
        data = backend.parse_apk_search(
            "firefox-140.1.0-r0 - Mozilla browser\n"
            "lib-foo-2-1.2-r3 - demo\nnot a package\n"
        )
        self.assertEqual([p["name"] for p in data], ["firefox", "lib-foo-2"])
        self.assertEqual(data[0]["version"], "140.1.0")
        self.assertFalse(data[0]["installed"])

    def test_no_duplicate_apk(self):
        self.assertEqual(len(backend.parse_apk_search(
            "foo-1.0-r0 - one\nfoo-1.1-r0 - two"
        )), 1)

    def test_apk_installed(self):
        self.assertEqual(backend.parse_apk_installed("bash\napk-tools\n")[1]["name"],
                         "apk-tools")

    def test_nix_search(self):
        output = json.dumps({"legacyPackages.x86_64-linux.hello": {
            "version": "2.12", "description": "Hello world"
        }})
        self.assertEqual(backend.parse_nix_search(output)[0]["name"], "hello")

    def test_nix_profile(self):
        output = json.dumps({"version": 3, "elements": {
            "0": {"attrPath": "legacyPackages.x86_64-linux.hello",
                  "originalUrl": "nixpkgs#hello"}
        }})
        data = backend.parse_nix_profile(output)
        self.assertEqual(data[0]["removeKey"], "0")
        self.assertEqual(data[0]["name"], "hello")

    def test_curated_discover_catalog(self):
        featured = backend.featured_packages()
        self.assertEqual(len(featured), 14)
        self.assertTrue(all(p["source"] == "apk" for p in featured))
        self.assertTrue(all(p["category"] != "Games" for p in featured))
        self.assertEqual(len(backend.featured_packages("Creative")), 3)
        self.assertEqual(backend.featured_packages("Office")[0]["name"], "libreoffice")
        with self.assertRaises(ValueError):
            backend.featured_packages("Gaming")

    def test_validation(self):
        for invalid in ("", "-danger", "bad space", "../escape", "a;id", "a"*129):
            with self.assertRaises(ValueError):
                backend.validate_name(invalid)
        self.assertEqual(backend.validate_name("firefox-esr"), "firefox-esr")

    def test_nix_invocation(self):
        self.assertEqual(backend.nix_cli("search", "nixpkgs", "hello")[-3:],
                         ["search", "nixpkgs", "hello"])


if __name__ == "__main__":
    unittest.main()
