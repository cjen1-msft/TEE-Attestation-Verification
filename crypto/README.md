# TEE Attestation Verification Crypto

Rather than implementing any cryptographic primitives, this crate dispatches these to one of several backends.
It narrowly exposes a unified surface for signature verification and certificate chain verification across native and WebCrypto backends.

## Backends

At least one target-compatible backend feature must be enabled. If multiple
backend features are enabled, `build.rs` selects the target-preferred backend.

| Feature | Platforms | sync | async | Notes |
|---|---|---:|---:|---|
| `crypto_openssl` | Native | yes | yes | Uses OpenSSL for native certificate-chain verification and primitive verification. |
| `crypto_webcrypto` | WASM | no | yes | Uses `globalThis.crypto.subtle` for primitive verification and the shared X.509 path validator. |
| `crypto_windows` | Windows | yes | yes | Uses Windows CNG for primitive verification and Crypt32 for certificate-chain verification. |

Windows targets prefer `crypto_windows` whenever it is enabled, including when
`crypto_openssl` is also enabled. Other native targets use `crypto_openssl`.
WASM targets use `crypto_webcrypto`.
Use `--no-default-features --features crypto_windows` to select only the
Windows backend.

## Scope

This crate is intentionally limited to just what is required to verify SNP attestations, and in the future UVM endorsements.
This narrow scope ensures we don't need to implement generic cryptographic primitives.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.