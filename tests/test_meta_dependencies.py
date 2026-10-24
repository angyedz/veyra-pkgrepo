"""Keep experimental/in-place updater out of the conventional desktop meta.

Veyra's current single-root installer must not receive an updater just
because it installs veyra-meta. Paired A/B updates will have a separate
trusted, signed system component instead of a desktop package dependency.
"""
from pathlib import Path
import re
import unittest


class MetaPackageDependencies(unittest.TestCase):
    def test_meta_never_installs_legacy_updater(self):
        recipe = (Path(__file__).resolve().parents[1] /
                  "src/veyra-meta/APKBUILD").read_text()
        match = re.search(r'^depends="([^"]*)"$', recipe, re.MULTILINE)
        self.assertIsNotNone(match, "Meta package must declare dependencies")
        packages = match.group(1).split()
        self.assertIn("vpkg", packages)
        self.assertIn("veyra-session", packages)
        self.assertNotIn("veyra-update", packages,
                         "Legacy in-place update must not be pulled as meta dependency")
        self.assertEqual(len(packages), len(set(packages)))

    def test_meta_revision_was_bumped(self):
        recipe = (Path(__file__).resolve().parents[1] /
                  "src/veyra-meta/APKBUILD").read_text()
        match = re.search(r"^pkgrel=(\d+)$", recipe, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertGreaterEqual(int(match.group(1)), 1)


if __name__ == "__main__":
    unittest.main()
