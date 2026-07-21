# TeeAttestationVerification for .NET

Linux x64 .NET 8 bindings for the repository's native TEE attestation
verification C ABI. The NuGet package includes the managed assembly and the
pure-Rust native library; consumers do not need a system OpenSSL runtime.

## Build and test

Run these commands from `ffi/csharp`:

```bash
jobs=$(( $(nproc) / 2 ))
CARGO_BUILD_JOBS="$jobs" dotnet build TeeAttestationVerification.sln -m:"$jobs"
CARGO_BUILD_JOBS="$jobs" dotnet test TeeAttestationVerification.sln -m:"$jobs"
```

The tests use xUnit v3 on Microsoft.Testing.Platform and exercise the native
library with the repository fixtures. `Debug` managed builds invoke Cargo's
`dev` profile; `Release` managed builds invoke Cargo with `--release`. The
MSBuild target builds
`target/{debug|release}/libtee_attestation_verification_ffi.so` with
`crypto_pure_rust` on each managed build; Cargo's incremental build only
recompiles it when needed. Running Cargo each time also prevents an artifact
built elsewhere with a different crypto feature from being reused accidentally.

## Pack

```bash
jobs=$(( $(nproc) / 2 ))
CARGO_BUILD_JOBS="$jobs" dotnet pack \
  TeeAttestationVerification/TeeAttestationVerification.csproj \
  -c Release -m:"$jobs"
```

The package places the native asset at:

```text
runtimes/linux-x64/native/libtee_attestation_verification_ffi.so
```

The managed interop declarations use the bare logical library name
`tee_attestation_verification_ffi`, allowing .NET's runtime asset resolver to
load the packaged `.so`.

## Platform and API behavior

- The initial supported runtime is Linux x64 only; MSBuild rejects other hosts
  and runtime identifiers. Release packages are built on Ubuntu 22.04, so the
  native binary requires glibc 2.35 or newer.
- `SnpAttestationReport`, `CborValue`, and `CoseSign1` are disposable. Owned
  native allocations are held by `SafeHandle` implementations.
- CBOR children are borrowed by the C ABI. Each managed child retains the owned
  root, so it remains usable after its parent wrapper is disposed. Borrowed byte
  and text views are copied before returning to managed code.
- Every native `TavError` is freed and surfaced as `VerifyException`, preserving
  its `ErrorCode` and message. Managed shape/format errors use standard argument
  or format exceptions.
- Task-returning APIs execute the synchronous native call before returning a
  completed or faulted task. Inputs are snapshotted first; no `Task.Run` or
  caller-owned buffer is retained.
- Individual inputs are capped at 1 GiB. Empty inputs are passed safely to the
  native validator, and null managed references are rejected without entering
  native code.
- `VerifySnpAttestationWithCertChainAsync` accepts exactly three PEM- or
  DER-encoded certificates ordered `[vcek, ask, ark]` and normalizes them to PEM
  in managed code. `SplitPemBundle` rejects non-whitespace outside certificate
  blocks; `SplitCertificateBundle` remains as an obsolete compatibility alias.
- `VerifyCaciAttestation` translates the minimum-TCB JSON map into the native
  CPUID/8-byte-TCB arrays and requires every trusted policy digest to be exactly
  32 bytes.
