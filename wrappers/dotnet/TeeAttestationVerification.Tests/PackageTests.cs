// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;

namespace TeeAttestationVerification.Tests;

public sealed class PackageTests
{
    [Fact]
    public void NuGetContainsManagedLibraryAndLinuxX64NativeAsset()
    {
        string project = Path.Combine(
            FixtureData.RepositoryRoot,
            "wrappers/dotnet/TeeAttestationVerification/TeeAttestationVerification.csproj");
        string output = Path.Combine(
            Path.GetTempPath(),
            nameof(TeeAttestationVerification),
            Guid.NewGuid().ToString("N"));
        string configuration = typeof(PackageTests).Assembly
            .GetCustomAttribute<AssemblyConfigurationAttribute>()!
            .Configuration;
        Directory.CreateDirectory(output);

        try
        {
            using Process process = Process.Start(new ProcessStartInfo(
                "dotnet",
                $"pack \"{project}\" --no-build --no-restore -c {configuration} -o \"{output}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            })!;
            string standardOutput = process.StandardOutput.ReadToEnd();
            string standardError = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert.True(
                process.ExitCode == 0,
                $"dotnet pack failed ({process.ExitCode}){Environment.NewLine}" +
                standardOutput + Environment.NewLine + standardError);

            string package = Directory.GetFiles(
                output, "TeeAttestationVerification.*.nupkg").Single();
            using ZipArchive archive = ZipFile.OpenRead(package);
            string[] entries = archive.Entries.Select(entry => entry.FullName).ToArray();

            Assert.Contains("lib/net8.0/TeeAttestationVerification.dll", entries);
            Assert.Contains(
                "runtimes/linux-x64/native/libtee_attestation_verification_ffi.so",
                entries);
            Assert.DoesNotContain(entries, entry =>
                entry.Contains("libssl", StringComparison.OrdinalIgnoreCase) ||
                entry.Contains("libcrypto", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(output, recursive: true);
        }
    }
}
