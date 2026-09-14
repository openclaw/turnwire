import unittest

from check_macos_target import check_target


def build_version(version, platform="1"):
    return f"""Load command 10
      cmd LC_BUILD_VERSION
  cmdsize 32
 platform {platform}
    minos {version}
      sdk 15.5
   ntools 1
"""


class DeploymentTargetTest(unittest.TestCase):
    def test_supported_targets(self):
        for version in ("11.0", "12.0", "12.0.0"):
            with self.subTest(version=version):
                self.assertEqual(check_target(build_version(version)), [version])

    def test_rejects_newer_target(self):
        for version in ("12.0.1", "12.1", "14.0", "15.0"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                check_target(build_version(version))

    def test_checks_all_architectures(self):
        with self.assertRaises(ValueError):
            check_target(build_version("12.0") + build_version("15.0"))
        self.assertEqual(
            check_target(build_version("12.0") + build_version("12.0")),
            ["12.0", "12.0"],
        )

    def test_rejects_missing_malformed_or_non_macos_target(self):
        for commands in ("", "not Mach-O", build_version("unknown"),
                         build_version("12.0", platform="2")):
            with self.subTest(commands=commands), self.assertRaises(ValueError):
                check_target(commands)

    def test_legacy_command(self):
        self.assertEqual(check_target("""Load command 9
      cmd LC_VERSION_MIN_MACOSX
  cmdsize 16
  version 12.0
      sdk 15.5
"""), ["12.0"])


if __name__ == "__main__":
    unittest.main()
