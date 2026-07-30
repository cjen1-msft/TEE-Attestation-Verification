# CACI C# demo

This demo verifies the checked-in Confidential ACI fixture through the packaged
`TeeAttestationVerification` NuGet, the Linux x64 .NET binding over the native
TEE attestation verification C ABI.

The demo references the library as a `<PackageReference>` and builds against
the packed `.nupkg` restored from a temporary local feed, so it exercises the
NuGet → C# → C ABI → Rust path that a downstream .NET developer uses.

It runs the `demos/caci-c-ffi/` scenario: the same positional arguments, the
same minimum-TCB entry, and byte-identical stdout. `run_tests.py` asserts that
equality, so the C and C# bindings cannot drift apart.

The demo hardcodes one minimum-TCB entry for the Milan fixture: CPUID
`0x00A00F11` with minimum TCB bytes `04000000000018db`, passed as a
`(uint Cpuid, ReadOnlyMemory<byte> Tcb)` pair.

## Prerequisites

- a Linux x64 process;
- the .NET 8 SDK;
- OpenSSL 3 (`libssl.so.3` and `libcrypto.so.3`) at runtime;
- Rust and the OpenSSL development headers to build the native library, which
  the package build invokes through Cargo.

## Run

The demo consumes the packaged NuGet, so build it against a local feed
containing the packed package:

```sh
dotnet pack ffi/csharp/TeeAttestationVerification/TeeAttestationVerification.csproj \
  --configuration Release --output /tmp/tav-feed -p:PackageVersion=1.0.4

dotnet restore demos/caci-csharp/TavCaciCsharpDemo.csproj \
  --source /tmp/tav-feed --source https://api.nuget.org/v3/index.json

dotnet run --project demos/caci-csharp/TavCaciCsharpDemo.csproj --no-restore -- \
  caci/tests/fixtures/report.hex \
  caci/tests/fixtures/host-amd-cert.base64 \
  caci/tests/fixtures/reference-info.base64 \
  'did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2' \
  demos/caci-c-ffi/test-data/policy.hex \
  ContainerPlat-AMD-UVM \
  104
```

The positional arguments are
`<report.hex> <host-amd-cert.base64> <uvm.base64> <trusted-didx509> <policy.hex> <uvm-feed> <minimum-svn>`.
On success the demo prints the verified report to stdout and exits 0; on failure
it prints the error to stderr and exits 1.

## Tests

`run_tests.py` packs the library into a temporary local feed, restores and
builds the demo against that exact package, then checks the demo output against
the golden files in `test-data/`. It covers the success path, the empty-report
failure path, and a parity assertion that the golden is byte-identical to the C
demo's `demos/caci-c-ffi/test-data/sample-output.golden.txt`, so cross-binding
drift breaks the build. It uses Python's `unittest` framework and requires the
.NET 8 SDK and Rust:

```sh
python3 demos/caci-csharp/run_tests.py
```
