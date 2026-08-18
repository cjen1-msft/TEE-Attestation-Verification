#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Test the C# binding as a NuGet consumer.

Pack the binding into a temporary feed, restore the separate test project from
that package, and run the tests without rebuilding the binding from source.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
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
NATIVE_ASSETS = frozenset(
    {
        "runtimes/linux-x64/native/libtee_attestation_verification_ffi.so",
        "runtimes/osx-x64/native/libtee_attestation_verification_ffi.dylib",
        "runtimes/win-x64/native/tee_attestation_verification_ffi.dll",
    }
)
LOCAL_NATIVE_ASSETS = frozenset(
    {"runtimes/linux-x64/native/libtee_attestation_verification_ffi.so"}
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


def package_version(package: pathlib.Path) -> str:
    with zipfile.ZipFile(package) as archive:
        nuspecs = [name for name in archive.namelist() if name.endswith(".nuspec")]
        if len(nuspecs) != 1:
            raise RuntimeError(f"Expected one nuspec in {package}, found {nuspecs}")
        root = ElementTree.fromstring(archive.read(nuspecs[0]))

    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "version" and element.text:
            return element.text
    raise RuntimeError(f"{package} nuspec does not define a version")


def verify_package(
    package: pathlib.Path, expected_native_assets: frozenset[str]
) -> None:
    with zipfile.ZipFile(package) as archive:
        entries = set(archive.namelist())
        expected_managed = "lib/net8.0/TeeAttestationVerification.dll"
        expected_documentation = "lib/net8.0/TeeAttestationVerification.xml"
        if expected_managed not in entries:
            raise RuntimeError(f"{package} does not contain {expected_managed}")
        if expected_documentation not in entries:
            raise RuntimeError(f"{package} does not contain {expected_documentation}")
        native_assets = frozenset(
            entry
            for entry in entries
            if entry.startswith("runtimes/") and "/native/" in entry
        )
        if native_assets != expected_native_assets:
            raise RuntimeError(
                f"{package} native assets differ: expected "
                f"{sorted(expected_native_assets)}, found {sorted(native_assets)}"
            )
        if any(
            "libssl" in entry.lower() or "libcrypto" in entry.lower()
            for entry in entries
        ):
            raise RuntimeError("OpenSSL libraries must not be bundled in the package")


def find_package(path: pathlib.Path) -> pathlib.Path:
    if path.is_file():
        return path
    packages = list(path.glob("TeeAttestationVerification.*.nupkg"))
    if len(packages) != 1:
        raise RuntimeError(f"Expected one package in {path}, found {len(packages)}")
    return packages[0]


def write_nuget_config(path: pathlib.Path, feed: pathlib.Path) -> None:
    configuration = ElementTree.Element("configuration")
    sources = ElementTree.SubElement(configuration, "packageSources")
    ElementTree.SubElement(sources, "clear")
    ElementTree.SubElement(
        sources, "add", key="test-feed", value=str(feed)
    )
    ElementTree.SubElement(
        sources,
        "add",
        key="nuget.org",
        value="https://api.nuget.org/v3/index.json",
    )
    mappings = ElementTree.SubElement(configuration, "packageSourceMapping")
    local_mapping = ElementTree.SubElement(
        mappings, "packageSource", key="test-feed"
    )
    ElementTree.SubElement(
        local_mapping, "package", pattern="TeeAttestationVerification"
    )
    public_mapping = ElementTree.SubElement(
        mappings, "packageSource", key="nuget.org"
    )
    ElementTree.SubElement(public_mapping, "package", pattern="*")
    ElementTree.ElementTree(configuration).write(
        path, encoding="utf-8", xml_declaration=True
    )


def run_tests(configuration: str, supplied_package: pathlib.Path | None) -> None:
    with tempfile.TemporaryDirectory(prefix="tav-csharp-tests-") as temporary:
        temp = pathlib.Path(temporary)
        feed = temp / "feed"
        feed.mkdir()
        env = os.environ.copy()
        env["NUGET_PACKAGES"] = str(temp / "packages")

        if supplied_package is None:
            version = test_package_version()
            run(
                [
                    "dotnet",
                    "pack",
                    str(PACKAGE_PROJECT),
                    "--configuration",
                    configuration,
                    "--output",
                    str(feed),
                    f"-p:PackageVersion={version}",
                ],
                env=env,
            )
            package = find_package(feed)
            expected_native_assets = LOCAL_NATIVE_ASSETS
        else:
            package = find_package(supplied_package.resolve())
            shutil.copy2(package, feed)
            package = feed / package.name
            version = package_version(package)
            expected_native_assets = NATIVE_ASSETS

        verify_package(package, expected_native_assets)
        nuget_config = temp / "NuGet.Config"
        write_nuget_config(nuget_config, feed)

        common_properties = [
            f"-p:TavPackageVersion={version}",
        ]
        run(
            [
                "dotnet",
                "restore",
                str(TEST_PROJECT),
                "--configfile",
                str(nuget_config),
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
                *common_properties,
            ],
            env=env,
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pack TeeAttestationVerification and run its public consumer tests"
    )
    parser.add_argument("--configuration", default="Release")
    parser.add_argument(
        "--package",
        type=pathlib.Path,
        help="Existing package file or directory to test without rebuilding",
    )
    args = parser.parse_args()

    run_tests(args.configuration, args.package)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
