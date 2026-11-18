# TEE Attestation Verification Crypto

Rather than implementing any cryptographic primitives, this crate dispatches these to one of several backends.
It narrowly exposes a unified surface for signature verification and certificate chain verification across native and WebCrypto backends.
There is a fallback pure-rust backend for workloads that don't have webcrypto or openssl available.

## Backends

At least one target-compatible backend feature must be enabled. If multiple
backend features are enabled, `build.rs` selects the target-preferred backend.

| Feature | Platforms | sync | async | Notes |
|---|---|---:|---:|---|
| `crypto_openssl` | Native | yes | yes | Uses OpenSSL for native certificate-chain verification and primitive verification. |
| `crypto_webcrypto` | WASM | no | yes | Uses `globalThis.crypto.subtle` for primitive verification and the shared X.509 path validator. |
| `crypto_pure_rust` | Native, WASM | yes | yes | Uses RustCrypto crates and the shared X.509 path validator. |
| `crypto_windows` | Windows | yes | yes | Uses Windows CNG and Crypt32 for signatures and the shared X.509 path validator. |

Windows targets prefer `crypto_windows` whenever it is enabled, including when
`crypto_openssl` is also enabled. Other native targets prefer `crypto_openssl`
when enabled, then `crypto_pure_rust`.
WASM targets prefer `crypto_webcrypto` when enabled, then `crypto_pure_rust`.
Use `--no-default-features --features crypto_windows` to select only the
Windows backend.

## Certificate purpose

`CryptoBackend::verify_chain` and `AsyncCryptoBackend::verify_chain` verify a
certificate path without authorizing any particular use of the leaf. For a known
intended purpose, call `verify_chain_with_purpose` on the same trait with its
dotted-decimal OID as the last argument (e.g. `Some("1.3.6.1.5.5.7.3.3")` for
code signing). `None` is equivalent to `verify_chain`. Custom backends that
do not implement this method reject requested purposes by default.

All built-in backends reject malformed EKU on the verified path, even in
purpose-neutral mode. For a supplied purpose, a leaf with EKU must list that OID
or `anyExtendedKeyUsage`, whether the extension is critical or not. A leaf
without EKU is not restricted by EKU. This check is limited to RFC 5280 leaf
EKU; it doesn't validate leaf `keyUsage`, require explicit EKU, or apply an
application-specific purpose profile.

## Scope

This crate is intentionally limited to just what is required to verify SNP attestations, and in the future UVM endorsements.
This narrow scope ensures we don't need to implement generic cryptographic primitives.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.