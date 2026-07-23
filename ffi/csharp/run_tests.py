#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import argparse
import fcntl
import os
import pathlib
import subprocess
import tempfile
import uuid
import zipfile
import xml.etree.ElementTree as ElementTree


ROOT = pathlib.Path(__file__).resolve().parents[2]
CSHARP_ROOT = pathlib.Path(__file__).resolve().parent
PACKAGE_PROJECT = (
    CSHARP_ROOT / "TeeAttestationVerification" / "TeeAttestationVerification.csproj"
)
TEST_PROJECT = (
    CSHARP_ROOT
    / "TeeAttestationVerification.Tests"
    / "TeeAttestationVerification.Tests.csproj"
)
NATIVE_ASSET = (
    "runtimes/linux-x64/native/libtee_attestation_verification_ffi.so"
)
LOCK_FILE = (
    pathlib.Path(tempfile.gettempdir())
    / "tee-attestation-verification-csharp-tests.lock"
)


def run(command: list[str], *, env: dict[str, str]) -> None:
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def test_package_version() -> str:
    version = ElementTree.parse(PACKAGE_PROJECT).getroot().findtext(
        "./PropertyGroup/Version"
    )
    if not version:
        raise RuntimeError(f"{PACKAGE_PROJECT} does not define Version")
    return f"{version}-test.{uuid.uuid4().hex[:12]}"


def verify_package(package: pathlib.Path, native_library: pathlib.Path) -> None:
    with zipfile.ZipFile(package) as archive:
        entries = set(archive.namelist())
        expected_managed = "lib/net8.0/TeeAttestationVerification.dll"
        expected_documentation = "lib/net8.0/TeeAttestationVerification.xml"
        if expected_managed not in entries:
            raise RuntimeError(f"{package} does not contain {expected_managed}")
        if expected_documentation not in entries:
            raise RuntimeError(f"{package} does not contain {expected_documentation}")
        if NATIVE_ASSET not in entries:
            raise RuntimeError(f"{package} does not contain {NATIVE_ASSET}")
        if any(
            "libssl" in entry.lower() or "libcrypto" in entry.lower()
            for entry in entries
        ):
            raise RuntimeError("OpenSSL libraries must not be bundled in the package")
        native_library.write_bytes(archive.read(NATIVE_ASSET))

    dependencies = subprocess.run(
        ["readelf", "-d", str(native_library)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for dependency in ("[libssl.so.3]", "[libcrypto.so.3]"):
        if dependency not in dependencies:
            raise RuntimeError(
                f"{NATIVE_ASSET} does not declare the required {dependency[1:-1]}"
            )


def run_tests(configuration: str) -> None:
    jobs = max(1, (os.cpu_count() or 1) // 2)
    version = test_package_version()
    with tempfile.TemporaryDirectory(prefix="tav-csharp-tests-") as temporary:
        temp = pathlib.Path(temporary)
        feed = temp / "feed"
        feed.mkdir()
        env = os.environ.copy()
        env["CARGO_BUILD_JOBS"] = str(jobs)
        env["NUGET_PACKAGES"] = str(temp / "packages")

        run(
            [
                "dotnet",
                "pack",
                str(PACKAGE_PROJECT),
                "--configuration",
                configuration,
                f"-m:{jobs}",
                "--output",
                str(feed),
                f"-p:PackageVersion={version}",
            ],
            env=env,
        )

        packages = list(feed.glob("TeeAttestationVerification.*.nupkg"))
        if len(packages) != 1:
            raise RuntimeError(f"Expected one package, found {len(packages)}")
        package = packages[0]
        expected_name = f"TeeAttestationVerification.{version}.nupkg"
        if package.name != expected_name:
            raise RuntimeError(f"Expected {expected_name}, got {package.name}")
        verify_package(package, temp / "libtee_attestation_verification_ffi.so")

        common_properties = [
            f"-p:TavPackageVersion={version}",
        ]
        run(
            [
                "dotnet",
                "restore",
                str(TEST_PROJECT),
                "--source",
                str(feed),
                "--source",
                "https://api.nuget.org/v3/index.json",
                *common_properties,
            ],
            env=env,
        )
        run(
            [
                "dotnet",
                "test",
                str(TEST_PROJECT),
                "--configuration",
                configuration,
                "--no-restore",
                f"-m:{jobs}",
                *common_properties,
            ],
            env=env,
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pack TeeAttestationVerification and run its public consumer tests"
    )
    parser.add_argument("--configuration", default="Release")
    args = parser.parse_args()

    with LOCK_FILE.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        run_tests(args.configuration)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
