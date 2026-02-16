# C++ Example — TEE Attestation Verification

This example demonstrates calling the Rust `tav_verify_attestation`
function from C++ via the library's C FFI.

## Prerequisites

| Tool | Version |
|------|---------|
| Rust toolchain (`cargo`) | stable |
| CMake | ≥ 3.14 |
| C++17 compiler (gcc / clang) | any recent |
| OpenSSL (development headers + libraries) | ≥ 1.1 |

## Build

```bash
cd examples/cpp
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

This will:
1. Detect the repo root (in-tree build) or `FetchContent` it from GitHub.
2. Run `cargo build --release` to produce the static library (`.a`).
3. Find OpenSSL on the host via `find_package(OpenSSL)`.
4. Compile and link the C++ example against both.

## Run

```bash
./verify_example <report.bin> <ark.pem> <ask.pem> <vcek.pem>
```

For example, using the included test data:

```bash
./verify_example \
    ../../../tests/test_data/milan_attestation_report.bin \
    ../../../src/snp/root_certs/milan_ark.pem \
    ../../../tests/test_data/milan_ask.pem \
    ../../../tests/test_data/milan_vcek.pem
```

On success, all report fields are printed:

```
verification succeeded

  version:          3
  guest_svn:        2
  policy:           0x3001f
  family_id:        01000000000000000000000000000000
  image_id:         02000000000000000000000000000000
  vmpl:             0
  signature_algo:   1
  platform_version: 04000000000018db
  ...
```

On failure, an error code and message are printed:

```
verification failed (code 103): Certificate chain error: "verification failed at depth 0: unable to get local issuer certificate"
```

## Linking in your own project

The CMakeLists.txt creates a `tav` imported library target that carries
OpenSSL and system dependencies (pthread, dl, m) as transitive
`INTERFACE_LINK_LIBRARIES`. In your own CMake project you only need:

```cmake
target_link_libraries(my_app PRIVATE tav)
```

## Out-of-tree / standalone usage

When this `examples/cpp/` directory is copied out of the repository, CMake
will automatically fetch the repo via `FetchContent` from GitHub — no manual
clone required.
