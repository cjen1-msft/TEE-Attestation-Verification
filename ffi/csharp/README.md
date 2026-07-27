# TeeAttestationVerification for .NET

Linux x64 .NET 8 bindings for the repository's native TEE attestation
verification C ABI. The NuGet package includes the managed assembly and the
OpenSSL-backed native library. Consumers must provide the OpenSSL 3 runtime
libraries (`libssl.so.3` and `libcrypto.so.3`).

## Install

Add the package from your configured NuGet feed:

```bash
dotnet add package TeeAttestationVerification --version 1.0.4
```

The runtime environment must provide:

- a Linux x64 process;
- glibc 2.35 or newer;
- OpenSSL 3 (`libssl.so.3` and `libcrypto.so.3`).

Native calls from unsupported operating systems or process architectures throw
`PlatformNotSupportedException`.

## Verify an SNP attestation

```csharp
using TeeAttestationVerification;

byte[] reportBytes = File.ReadAllBytes("attestation-report.bin");
string arkPem = File.ReadAllText("ark.pem");
string askPem = File.ReadAllText("ask.pem");
string vcekPem = File.ReadAllText("vcek.pem");

try
{
    using SnpAttestationReport report =
        AttestationVerifier.VerifySnpAttestation(
            reportBytes,
            arkPem,
            askPem,
            vcekPem);

    Console.WriteLine(Convert.ToHexString(report.Measurement()));
}
catch (VerifyException error)
{
    Console.Error.WriteLine($"{error.Code}: {error.Message}");
}
```

`VerifySnpAttestation` authenticates the AMD certificate chain and SNP report
signature before returning report claims.

## Ownership and errors

- `SnpAttestationReport`, `CborValue`, and `CoseSign1` own native handles and
  implement `IDisposable`. Dispose every returned object.
- CBOR navigation and COSE validation return independently owned views; parents
  and children may be disposed in any order.
- Byte-returning methods return managed copies.
- Native failures become `VerifyException` with a stable `ErrorCode`. Managed
  shape and format failures use standard argument or format exceptions.
- Verification is synchronous. Inputs are copied before entering native code.

`CaciPolicyDigests` validates, copies, and flattens trusted 32-byte CACI policy
digests once so the immutable collection can be reused. `VerifyCaciAttestation`
accepts minimum-TCB policy as a sequence of `(uint Cpuid, ReadOnlyMemory<byte>
Tcb)` pairs. Each TCB must contain exactly eight bytes, and CPUIDs must be
unique. The raw byte layout is `[boot loader, TEE, reserved x4, SNP, microcode]`
for Milan/Genoa and `[FMC, boot loader, TEE, SNP, reserved x3, microcode]` for
Turin. Pass an empty sequence for no minimum.

The package includes XML API documentation for IDE hover and IntelliSense.

## Build and test from source

Run from `ffi/csharp`:

```bash
python3 run_tests.py --configuration Release
```

The runner packs a uniquely versioned NuGet into a temporary feed, restores the
public xUnit consumer suite against that exact package, and tests the complete
NuGet → C# → C ABI → Rust path. It also checks the package layout and OpenSSL
dependencies.

Source builds require Rust, the OpenSSL development headers, and `pkg-config`.
The MSBuild project invokes Cargo with `crypto_openssl` for every build.

To create a release package:

```bash
jobs=$(( $(nproc) / 2 ))
CARGO_BUILD_JOBS="$jobs" dotnet pack \
  TeeAttestationVerification/TeeAttestationVerification.csproj \
  --configuration Release \
  -m:"$jobs"
```

The native asset is packaged at
`runtimes/linux-x64/native/libtee_attestation_verification_ffi.so`.
