---
name: ffi-testing
description: >-
  Test changes to the TAV C, C++, WASM, and C# FFI surfaces. Use when exported
  functions, handles, constants, ownership rules, errors, goldens, or consumer
  tests change under ffi/.
argument-hint: "[c|cpp|wasm|csharp] [errors|byte_buffer|cbor|snp|cose|caci]"
---

# FFI testing

Treat each consumer suite as an external user of its public surface.

## Cross-language synchronization

For every changed function, constant, error, or ownership contract, trace its
Rust implementation through C, C++, WASM, and C#. Identify which bindings expose
it before editing. Update each affected binding, consumer suite, and reference
document in the same change.

Use the same fixtures and expected values to compare shared behavior across
bindings. Preserve intentional language differences, such as C error pointers
versus C++ exceptions. Document unsupported surfaces and deliberate differences;
do not invent a new binding solely to make the surfaces identical.

Keep synchronization checks in the normal test or CI path. A manual comparison
is not a completeness guarantee. When declarations move between headers, update
every checker that reads those declarations, including Rust and managed tests.

## Required coverage

1. Enumerate the complete changed public surface from its authoritative source:
   - Rust: implementations and shared constants under `ffi/src`
   - C: `ffi/include/tav/*.h`
   - C++: `ffi/include/tav/*.hpp`
   - WASM: exported items in `ffi/src/wasm_ffi` and shared exports in `ffi/src/lib.rs`
   - C#: public types and members under `ffi/csharp/TeeAttestationVerification`
2. Exercise every matching function, property, enum member, and ownership
   operation in the corresponding consumer suite.
3. Assert behavior with known values or negative cases; successful invocation
   alone is insufficient.
4. Test owned handles, borrowed byte views, null/error behavior, and
   out-parameter reset rules where applicable.
5. Update goldens only alongside behavioral tests.

## C++ headers and ownership

- Compile each public C header independently as C and each C++ header
  independently as C++ in the consumer build. Include each twice to check include
  guards. Do not prepend `support.h` or another umbrella header that can hide
  missing includes. Keep this coverage complete when headers are added or moved.
- Cover move construction, self-move assignment, assignment over an owned
  value, moves from already-moved sources, and reuse of moved-from objects for
  every movable wrapper. Check destination values and the documented source
  state. Do not assume an unspecified moved-from exception message is preserved.
- Check borrowed raw getters, their empty-state behavior, and ownership after
  moves. Adoption tests must cover null and valid owned handles; document that
  adopting the same non-null pointer twice does not transfer ownership safely.
- Distinguish handle presence from payload length. Test default, moved-from,
  and live zero-length states where the API can produce them.
- Run the C++ consumer executable under AddressSanitizer with both shared and
  static linking. Do not describe this as instrumenting Rust unless the Rust
  library is also built with sanitizer instrumentation.

## ABI constants

When constants change:

1. Keep explicit test mappings between compiled Rust constants and their C
   names. Compare values and exact name sets in both directions.
2. For C++, initialize members from the C constants and check exact member sets
   and mappings in both directions. Equal values alone do not detect omitted
   members. Keep `ffi/tests/cpp-consumer/check_error_codes.py` pointed at the
   authoritative error headers.
3. For constants exposed in C#, keep explicit C-name-to-managed-name mappings.
   Parse the public C header and compare values and exact member sets with the
   reflected managed enum.
4. For WASM, check the exported names and values against the shared Rust
   constants. Include exports from `ffi/src/lib.rs`, not only `wasm_ffi`.
5. Reject missing, extra, duplicate, or mismatched members. Do not update only
   one side to make a test pass.
6. Use named Rust constants in runtime logic and tests; do not repeat numeric
   literals in match arms and equivalence tests.
7. Keep function signatures, handle ownership, and boolean/layout checks outside
   constant-equivalence tests.
8. When adding or changing a synchronization checker, temporarily add a member
   to its actual source declaration and run the normal test command. Confirm
   failure, add the matching binding member, and confirm success. Remove both
   temporary edits and rerun. Also exercise missing, extra, duplicate, and
   incorrectly mapped cases.

## Validation

Use half-machine concurrency for builds.

- Native Rust: `crypto_openssl`
- C consumer: shared and static
- C++ consumer: shared and static under ASan, standalone headers, and enum
  completeness through `ffi/tests/cpp-consumer/CMakeLists.txt`
- WASM consumer: `crypto_webcrypto`
- C#: `python3 ffi/csharp/run_tests.py --configuration Release`
- Repository: formatting, version sync, license headers, and `git diff --check`
