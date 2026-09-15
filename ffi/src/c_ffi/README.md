# C ABI

Native C ABI for CBOR, SNP, COSE, and CACI verification. Headers live under
`ffi/include/tav/`; each header's usage summary documents its own surface in
more detail (`cbor.h`, `snp.h`, `cose.h`, `caci.h`, `errors.h`, `byte_buffer.h`).

C++ consumers can use the RAII wrappers instead of the raw C ABI: `errors.hpp`
(`tav::Exception`), `byte_buffer.hpp` (`tav::ByteBuffer`), and `snp.hpp`
(`tav::snp::Report`). `utils.h` includes both C utility headers. See
`ffi/tests/cpp-consumer/` for worked examples and
`ffi/tests/cpp-consumer/CMakeLists.txt` for a CMake setup.
The C++ consumer executable runs with AddressSanitizer enabled for both shared
and static linking. The Rust library is not sanitizer-instrumented.

The CBOR wrapper in `cbor.hpp` uses the shared `tav::Exception` and
`tav::ErrorCode` from `errors.hpp`. Catch `tav::Exception` and inspect `code()`.
Errors retain the native C ABI code and message, including `CBOR_ENCODE_FAILED`
for invalid builder inputs. The former CBOR-specific exception classes and
`tav::cbor::Error` enum are removed. `rethrow_with_msg` prefixes the message
of any `tav::Exception` and preserves its code.
Serialization returns an owned `std::vector<uint8_t>`. See
`ffi/tests/c-builder/` for CBOR examples and a CMake setup.

Fallible public functions return `NULL` on success or an owned `TavError*` on
failure. Inspect failures with `tav_error_code`/`tav_error_message`, then free
them with `tav_error_free`. Owned handle out-parameters are reset to `NULL`
before any fallible work and set only on success.

If an entry point's implementation panics (e.g. on a bug triggered by
malformed input), the panic is caught at the FFI boundary and reported as a
`TAV_ERROR_PANIC` error instead of aborting the host process.

## Building and linking

```sh
cargo build --manifest-path ffi/Cargo.toml
```

That produces `libtee_attestation_verification_ffi.{a,so}` under
`target/debug/`. Link against it and include `ffi/include/tav/`. See
`ffi/tests/c-consumer/CMakeLists.txt`
for a worked CMake setup, including static linking.

## Generic CBOR

`tav/cbor.h` exposes builders, deterministic and non-deterministic parsing,
serialization, copies, and navigation through opaque `TavCborHandle*` handles.
`tav/cbor.hpp` provides the C++ RAII wrapper. Failures use the shared
`tav::Exception` and `tav::ErrorCode`.

The generic API borrows input byte and text buffers. Keep each buffer alive
and unmodified while any derived handle is in use, including projected
children and shallow copies. `tav_cbor_deep_copy` copies all payloads.
Navigation returns independently owned handles, so you can free a parent
before its children. Release every handle with `tav_cbor_free`.

Container builders consume input handles and clear their slots. Duplicate
or null handles reject the whole batch without consuming it. Output slots
must not alias input slots. Parsing and serialization enforce a maximum
depth of `TAV_CBOR_MAX_DEPTH`; builders do not limit nesting.

Serialization returns an owned `TavByteBuffer*`. Read it with
`tav_byte_buffer_data` and `tav_byte_buffer_len`, then release it with
`tav_byte_buffer_free`. Errors use the shared `TavError*` API, not separate
message buffers. Generic CBOR failures have `TAV_ERROR_CBOR_*` codes.

```c
TavCborHandle *value = NULL;
TavByteBuffer *encoded = NULL;
TavError *error = tav_cbor_make_signed(42, &value);
if (error == NULL) {
	error = tav_cbor_det_serialize(value, TAV_CBOR_MAX_DEPTH, &encoded);
}
if (error != NULL) {
	fprintf(stderr, "%s\n", tav_error_message(error));
	tav_error_free(error);
}
tav_byte_buffer_free(encoded);
tav_cbor_free(value);
```

## COSE and CACI handles

CBOR, COSE validation and verification, and CACI use `TavCborHandle*`.
`tav/cose.h` declares only COSE functions and constants. All native CBOR
operations are declared in `tav/cbor.h`.

Parsing borrows byte and text payloads. To detach a parsed value from its input,
call `tav_cbor_deep_copy` while the input remains alive, then free the borrowed
handle. COSE validation returns an independently owned view of the same
document. Borrowed input must outlive that view too. CACI verification instead
returns a document with owned payloads.

Use `tav_cbor_make_signed` or `tav_cbor_make_string` to create a map key, then
call `tav_cbor_map_at` and free the key. Only `TAV_ERROR_CBOR_KEY_NOT_FOUND`
means the key is absent. Other failures must not be treated as absence.
Map keys may themselves be arrays or maps. To read both sides of an entry,
call `tav_cbor_map_key_at` and `tav_cbor_map_value_at`; release the key if the
second call fails.

Readers use `TAV_ERROR_CBOR_*` codes and leave scalar and borrowed outputs
unchanged on failure. Owned output slots are reset before work.
Free each owned handle exactly once with `tav_cbor_free`.

C# uses this native API while retaining its public methods, kind values,
owned-input behavior, and 64-level depth limit. Its CBOR errors use the generic
codes described in the [C# binding documentation](../../csharp/README.md).
The independent WASM API remains unchanged.

For a complete example, see
[`print_uvm_endorsement`](../../../demos/caci-c-ffi/demo.c), which reads a CACI
result with the generic CBOR API and keeps its borrowed input alive.

## SNP verification

```c
TavSnpAttestationReport *report = NULL;
TavError *error = tav_verify_snp_attestation(
    report_bytes, report_len,
    ark_pem, ark_pem_len,
    ask_pem, ask_pem_len,
    vcek_pem, vcek_pem_len,
    &report);
if (error != NULL) { /* inspect, then tav_error_free(error); */ }

const uint8_t *measurement = NULL;
size_t measurement_len = 0;
tav_snp_attestation_report_measurement(report, &measurement, &measurement_len);

tav_snp_attestation_report_free(report);
```

## CACI verification

CACI verification is staged: verify the SNP attestation and the UVM
endorsement independently, then check the relying-party policy over both
verified handles.

```c
TavSnpAttestationReport *attestation = NULL;
tav_verify_snp_attestation(report_bytes, report_len, ark_pem, ark_pem_len,
                            ask_pem, ask_pem_len, vcek_pem, vcek_pem_len,
                            &attestation);

TavCborHandle *uvm = NULL;
tav_verify_caci_uvm_endorsement(uvm_bytes, uvm_len, trusted_didx509,
                                 trusted_didx509_len, &uvm);

TavByteBuffer *report_data = NULL;
TavError *error = tav_verify_caci_attestation(
    attestation,
    minimum_tcb_cpuids, minimum_tcb_values, minimum_tcb_count,
    trusted_policy_digests, trusted_policy_digest_count,
    uvm, uvm_feed, uvm_feed_len, minimum_svn,
    &report_data);

tav_cbor_free(uvm);
tav_snp_attestation_report_free(attestation);
```

`report_data` is the verified 64-byte SNP `REPORT_DATA`; read it with
`tav_byte_buffer_data`/`tav_byte_buffer_len` and release it with
`tav_byte_buffer_free`. See `ffi/tests/c-consumer/caci.cpp` for the failure
modes and full error handling.
