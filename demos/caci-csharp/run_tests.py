#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Pack the NuGet, build the CACI C# demo against it, and check its output.

The demo consumes the packaged ``TeeAttestationVerification`` NuGet rather than a
project reference, so this runner first packs a uniquely versioned package into a
temporary local feed and restores the demo from that feed, exactly like
``ffi/csharp/run_tests.py``. It then runs the built demo and compares its output
against the checked-in golden files.

Run it directly::

    python3 demos/caci-csharp/run_tests.py

or through the unittest CLI::

    python3 -m unittest discover --start-directory demos/caci-csharp \
        --pattern run_tests.py
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
import uuid
import xml.etree.ElementTree as ElementTree
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEMO_DIR.parents[1]
TEST_DATA = DEMO_DIR / "test-data"
C_DEMO_TEST_DATA = REPO_ROOT / "demos" / "caci-c-ffi" / "test-data"
DEMO_PROJECT = DEMO_DIR / "TavCaciCsharpDemo.csproj"
PACKAGE_PROJECT = (
    REPO_ROOT
    / "ffi"
    / "csharp"
    / "TeeAttestationVerification"
    / "TeeAttestationVerification.csproj"
)
DEMO_ASSEMBLY = "TavCaciCsharpDemo"
CONFIGURATION = "Release"
NUGET_ORG = "https://api.nuget.org/v3/index.json"

# These arguments mirror the CACI C FFI demo so both bindings produce identical
# output. The policy fixture is shared from the C demo's test-data directory.
TRUSTED_DIDX509 = (
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s"
    "::eku:1.3.6.1.4.1.311.76.59.1.2"
)
UVM_FEED = "ContainerPlat-AMD-UVM"
MINIMUM_SVN = "104"


def demo_args(report_path: Path) -> list[str]:
    """Build the positional argument list the demo expects."""
    return [
        str(report_path),
        str(REPO_ROOT / "caci" / "tests" / "fixtures" / "host-amd-cert.base64"),
        str(REPO_ROOT / "caci" / "tests" / "fixtures" / "reference-info.base64"),
        TRUSTED_DIDX509,
        str(C_DEMO_TEST_DATA / "policy.hex"),
        UVM_FEED,
        MINIMUM_SVN,
    ]


def build_environment(temp: Path) -> dict[str, str]:
    """Return an environment with an isolated NuGet cache and cargo job cap."""
    env = os.environ.copy()
    env["CARGO_BUILD_JOBS"] = str(max(1, (os.cpu_count() or 1) // 2))
    env["NUGET_PACKAGES"] = str(temp / "packages")
    env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
    env["DOTNET_NOLOGO"] = "1"
    return env


def package_version() -> str:
    """Derive a unique test package version from the package project."""
    version = ElementTree.parse(PACKAGE_PROJECT).getroot().findtext(
        "./PropertyGroup/Version"
    )
    if not version:
        raise RuntimeError(f"{PACKAGE_PROJECT} does not define Version")
    return f"{version}-test.{uuid.uuid4().hex[:12]}"


def build_demo(temp: Path, env: dict[str, str]) -> Path:
    """Pack the NuGet into a temp feed, restore the demo from it, and build.

    Returns the path to the demo executable.
    """
    feed = temp / "feed"
    feed.mkdir()
    output = temp / "build"
    version = package_version()
    properties = [f"-p:TavPackageVersion={version}"]

    subprocess.run(
        [
            "dotnet",
            "pack",
            str(PACKAGE_PROJECT),
            "--configuration",
            CONFIGURATION,
            "--output",
            str(feed),
            f"-p:PackageVersion={version}",
        ],
        check=True,
        cwd=REPO_ROOT,
        env=env,
    )
    subprocess.run(
        [
            "dotnet",
            "restore",
            str(DEMO_PROJECT),
            "--source",
            str(feed),
            "--source",
            NUGET_ORG,
            *properties,
        ],
        check=True,
        cwd=REPO_ROOT,
        env=env,
    )
    subprocess.run(
        [
            "dotnet",
            "build",
            str(DEMO_PROJECT),
            "--configuration",
            CONFIGURATION,
            "--no-restore",
            "--output",
            str(output),
            *properties,
        ],
        check=True,
        cwd=REPO_ROOT,
        env=env,
    )
    return output / DEMO_ASSEMBLY


class CaciCsharpDemoTest(unittest.TestCase):
    """Builds the packaged demo once and checks it against the golden files."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._temp = tempfile.TemporaryDirectory(prefix="tav-caci-csharp-demo-")
        try:
            temp = Path(cls._temp.name)
            cls.env = build_environment(temp)
            cls.binary = build_demo(temp, cls.env)
        except BaseException:
            cls._temp.cleanup()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temp.cleanup()
        super().tearDownClass()

    def run_demo(self, report_path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.binary), *demo_args(report_path)],
            cwd=REPO_ROOT,
            env=self.env,
            capture_output=True,
            text=True,
        )

    def test_verifies_fixture_matches_golden(self) -> None:
        result = self.run_demo(REPO_ROOT / "caci" / "tests" / "fixtures" / "report.hex")
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = (TEST_DATA / "sample-output.golden.txt").read_text()
        self.assertEqual(result.stdout, expected)

    def test_empty_report_reports_error(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".hex") as empty_report:
            result = self.run_demo(Path(empty_report.name))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(result.stdout, "")
        expected = (TEST_DATA / "empty-report-error.golden.txt").read_text()
        self.assertEqual(result.stderr, expected)

    def test_golden_matches_c_demo_golden(self) -> None:
        csharp_golden = (TEST_DATA / "sample-output.golden.txt").read_bytes()
        c_golden = (C_DEMO_TEST_DATA / "sample-output.golden.txt").read_bytes()
        self.assertEqual(
            csharp_golden,
            c_golden,
            "C# demo golden must be byte-identical to the C demo golden; "
            "the two bindings are expected to produce the same output.",
        )


if __name__ == "__main__":
    unittest.main()
