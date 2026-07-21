# rego-cpp C# packaging study

Research snapshot: [`microsoft/rego-cpp@4fd460a`](https://github.com/microsoft/rego-cpp/tree/4fd460ac7573754476d9d22be670c03b18a3245a), 2026-07-14.

## How rego-cpp packages its C# binding

rego-cpp keeps its managed binding in
[`wrappers/dotnet`](https://github.com/microsoft/rego-cpp/tree/4fd460ac7573754476d9d22be670c03b18a3245a/wrappers/dotnet).
The managed `Rego` assembly is a thin wrapper over the stable C ABI in
[`rego_c.h`](https://github.com/microsoft/rego-cpp/blob/4fd460ac7573754476d9d22be670c03b18a3245a/include/rego/rego_c.h):

- [`LibraryImport("rego_shared")`](https://github.com/microsoft/rego-cpp/blob/4fd460ac7573754476d9d22be670c03b18a3245a/wrappers/dotnet/Rego/Interpreter.cs)
  uses the platform-neutral library name and leaves resolution to .NET.
- Owned interpreter, output, input, and bundle pointers are represented by
  `SafeHandle` subclasses. Non-owning result nodes retain raw pointers into an
  owning output.
- Native error codes are converted to managed `RegoException` instances.
- The managed project
  [`Rego.csproj`](https://github.com/microsoft/rego-cpp/blob/4fd460ac7573754476d9d22be670c03b18a3245a/wrappers/dotnet/Rego/Rego.csproj)
  invokes CMake before the managed build, copies the resulting shared library
  beside the managed build output, and packs it under
  `runtimes/<rid>/native/`.
- Linux uses `librego_shared.so`, the `linux-x64` RID, and the OpenSSL 3
  backend. The package also supports Windows x64 and macOS x64/arm64.
- The project targets .NET 8 by default and .NET 8 plus .NET 9 when its
  `Multitarget` property is enabled.

The release workflow
[`build_nuget.yml`](https://github.com/microsoft/rego-cpp/blob/4fd460ac7573754476d9d22be670c03b18a3245a/.github/workflows/build_nuget.yml)
builds and tests on each supported host, then uploads one package artifact per
host. It does not merge those native assets into a single multi-RID package or
publish to NuGet.org in the public workflow.

rego-cpp's tests use xUnit and exercise real native calls through a project
reference. They cover representative interpreter and result-tree operations,
but do not pin every public managed member. The project-wide CI separately
tests the C++ core under sanitizers and checks a musl build, although the .NET
package itself does not contain a musl RID.

## Approach used for TAV

TAV follows the same interop and packaging boundary:

1. The existing `tee-attestation-verification-ffi` C ABI remains the sole
   native boundary; the managed package does not bind directly to Rust.
2. Source-generated `LibraryImport` declarations use the bare logical library
   name `tee_attestation_verification_ffi`.
3. Owned native errors, SNP reports, CBOR roots, and byte buffers use
   `SafeHandle`. Borrowed CBOR children retain their owning root, and borrowed
   native byte slices are copied before returning them to managed callers.
4. MSBuild invokes Cargo for the `crypto_openssl` Linux shared library,
   copies it to local build output, and packs
   `libtee_attestation_verification_ffi.so` as
   `runtimes/linux-x64/native/libtee_attestation_verification_ffi.so`.
5. The managed API mirrors the WASM API, substituting .NET types and naming:
   `Task` for promises, `byte[]`/`ReadOnlyMemory<byte>` for `Uint8Array`,
   `long`/`ulong` for JavaScript `bigint`, and managed exceptions for rejected
   promises.
6. xUnit native integration tests exercise every public managed API member and
   keep an approved reflection snapshot of the public surface.

## Intentional differences

- **Linux x64 only.** The first package has one supported RID. It does not
  imply support for Linux arm64, musl, Windows, or macOS.
- **Controlled glibc baseline.** Release packages are built on Ubuntu 22.04
  rather than a moving `ubuntu-latest` image. The initial native asset therefore
  targets glibc 2.35 or newer.
- **OpenSSL crypto backend.** Like rego-cpp's Linux package, TAV dynamically
  links to the system OpenSSL 3 runtime (`libssl.so.3` and `libcrypto.so.3`).
- **One package.** There is no per-host package merge problem while only one
  RID is supported.
- **Stronger API pinning.** Consumer tests are expected to cover the complete
  managed surface, matching the repository's existing C and WASM consumer-test
  convention.
- **Managed adapters fill C ABI gaps.** PEM bundle splitting, DER-to-PEM
  conversion, and minimum-TCB JSON translation live in C# because the WASM API
  exposes those shapes while the native ABI does not.

## Risks and follow-up criteria

- Adding another Linux architecture requires producing and testing its native
  library before adding the corresponding RID asset; changing only the NuGet
  path is insufficient.
- Alpine support requires a separately tested `linux-musl-*` artifact.
- CBOR children in the C ABI are borrowed, unlike the independently owned
  clones returned by the WASM binding. Managed lifetime tests must remain in
  place when this area changes.
- The native and managed package versions must move together at release time.

The package layout follows Microsoft's
[native files in .NET packages](https://learn.microsoft.com/nuget/create-packages/native-files-in-net-packages)
guidance, and the interop layer follows the
[native interop best practices](https://learn.microsoft.com/dotnet/standard/native-interop/best-practices)
for `LibraryImport` and `SafeHandle`.
