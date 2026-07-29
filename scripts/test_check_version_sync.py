# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("check-version-sync.py")
SPEC = importlib.util.spec_from_file_location("check_version_sync", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check_version_sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_version_sync)


class DotnetProjectPropertyTests(unittest.TestCase):
    def test_reads_effective_package_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = pathlib.Path(temporary) / "Example.csproj"
            project.write_text(
                """<Project Sdk=\"Microsoft.NET.Sdk\">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Version>1.0.4</Version>
    <PackageVersion>9.9.9</PackageVersion>
  </PropertyGroup>
</Project>
""",
                encoding="utf-8",
            )

            self.assertEqual(
                "9.9.9",
                check_version_sync.dotnet_project_property(
                    project, "PackageVersion"
                ),
            )


if __name__ == "__main__":
    unittest.main()
