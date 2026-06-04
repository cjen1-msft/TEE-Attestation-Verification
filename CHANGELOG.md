# Changelog

## [1.0.2]

[1.0.2]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-1.0.2

### Added

- Refactor to separate out crypto module and demos
- Refactor testing
  - Improve code coverage
- Refactor testing ci job
- Backend traits for signatures
- tighten chain verification
  - remove Certificate::verify<Certificate> as it could be easily misused
- Version script and trademark headers

## [1.0.1]

[1.0.1]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-1.0.1

### Added

- Expose a WASM certificate bundle splitter. (#49)

## [1.0.0]

[1.0.0]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-1.0.0

- First stable release of the TEE attestation verification library.
- Verifies AMD SEV-SNP attestation reports and collateral, including certificate chains, report signatures, and TCB values.
- Supports native Rust consumers with the `crypto_openssl` and `crypto_pure_rust` backends.
- Supports WebAssembly consumers with the `crypto_webcrypto` and `crypto_pure_rust` backends and generated `wasm-pack` wrapper output.
- Provides offline verification with caller-supplied certificates and optional `kds` verification that fetches AMD KDS collateral.

## [0.1.1]

[0.1.1]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-0.1.1

- If multiple backends are enabled, choose the backend appropriate to the target architecture, e.g. OpenSSL on native, WebCrypto on WASM (#44)

## [0.1.0]

[0.1.0]: https://github.com/microsoft/TEE-Attestation-Verification/releases/tag/tav-0.1.0

- Initial development release of the TEE attestation verification library.
- Supports native Rust consumers with the `crypto_openssl` and `crypto_pure_rust` backends.
- Supports WebAssembly consumers with the `crypto_webcrypto` and `crypto_pure_rust` backends and generated `wasm-pack` wrapper output.
- Rust consumers use tagged git dependencies with `tav-<crate-version>` tags.
- WASM consumers can use the GitHub release tarball containing the generated WebCrypto `pkg/` bundle.
