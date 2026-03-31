# Test Coverage

This crate splits test coverage into library tests and integration tests.

## Library Tests

- Live alongside the code under `src/`
- Cover backend-specific crypto behavior
- Run once per backend:
  - native `crypto_openssl`
  - native `crypto_pure_rust`
  - wasm `crypto_pure_rust`
  - wasm `crypto_webcrypto`

These runs cover backend-specific behavior such as certificate-chain verification,
report signature verification, and the WebCrypto-specific unit tests.

## Integration Tests

- Live under `tests/offline.rs` and `tests/online.rs`
- Cover end-to-end attestation verification flows
- Run with the `crypto_pure_rust` backend only

The pure-rust backend is used for integration coverage because it enables both
`sync_crypto` and `async_crypto`, so one backend can exercise both integration
paths on native and wasm.

## Wasm Runtimes

- Integration tests are Node-oriented and use `wasm_bindgen_test_configure!(run_in_node_experimental)`
- Browser coverage is provided by a separate wasm library-test run using a browser runner such as `wasm-pack test --headless --chrome`

The wasm test runtime is configured per test binary, so a single integration
target cannot cleanly serve both Node and browser execution. Keeping integration
targets Node-oriented avoids duplicating the mode-oriented test files.
