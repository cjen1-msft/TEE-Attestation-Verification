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

The CBOR wrapper in `cbor.hpp` includes `errors.hpp` and `byte_buffer.hpp` but retains its
`tav::cbor::DecodeError` and `tav::cbor::EncodeError` exceptions and error codes.
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
`tav/cbor.hpp` provides the C++ RAII wrapper with its existing signatures,
exception types, and `Error` and `Kind` values.

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

## Migrate CBOR calls from cose.h

The `tav_cbor_value_*` functions in `tav/cose.h` are deprecated. Their symbols,
signatures, error codes, messages, and output-reset rules remain compatible.
COSE validation and verification are **not deprecated**. Neither are the COSE
constants or the `TavCborValue` type used by those functions. C# and WASM APIs
are unchanged.

Include `tav/cbor.h` and use `TavCborHandle*` for new CBOR code. Replace calls
according to this table. All names below have the `tav_cbor_` prefix.

| Legacy suffix | Replacement suffix |
| --- | --- |
| `value_from_bytes` | `nondet_parse`, with depth 64 |
| `value_to_bytes` | `det_serialize`, with depth 64 |
| `value_kind` | `kind`, with `TAV_CBOR_HANDLE_KIND_*` constants |
| `value_int`, `value_simple`, `value_bytes`, `value_text` | `as_signed`, `as_simple`, `as_bytes`, `as_string` |
| `value_tag`, `value_len` | `as_tag`, `size` |
| `value_tagged_payload` | `as_tag`, then `tag_at` |
| `value_array_at`, `value_map_at` | `array_at`, `map_at` |
| `value_map_at_int`, `value_map_at_text` | `make_signed` or `make_string`, then `map_at`; free the key afterward |
| `value_map_has_key`, `value_map_has_int_key`, `value_map_has_text_key` | `map_at`; only `TAV_ERROR_CBOR_KEY_NOT_FOUND` means absent; free any result and error |
| `value_map_entry_at` | `map_key_at`, then `map_value_at`; free the key if the second call fails |
| `value_map_key_at`, `value_map_value_at` | `map_key_at`, `map_value_at` |
| `value_free` | `free` |

Legacy parsing copies payloads. Generic parsing borrows them. Keep the input
alive and unchanged until all derived handles are freed. If you need an owned
tree, call `tav_cbor_deep_copy` on the parsed handle before releasing the input,
then free the borrowed handle. Navigation shares the document without copying
payloads. Map lookup supports arbitrary CBOR keys, including arrays and maps.

Do not reuse legacy kind constants with `tav_cbor_kind`: their values differ.
Generic readers use `TAV_ERROR_CBOR_*` codes and leave scalar and borrowed
outputs unchanged on failure. Legacy readers clear those outputs. Both APIs
clear owned output slots before work. Keep depth 64 to preserve the legacy
parse and serialize limit; the generic API permits up to `TAV_CBOR_MAX_DEPTH`.

The opaque handle types have the same representation. Cast a handle pointer
explicitly when passing a generic value to COSE validation or verification,
or when reading a returned COSE or CACI handle with the generic API. This does
not copy data or create another ownership reference. Never cast a
pointer-to-pointer output slot. Use a variable of the declared output type,
then cast its value. Free each owned handle exactly once with `tav_cbor_free`.
Borrowed generic input must also outlive any validated COSE handle.

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

TavCborValue *uvm = NULL;
tav_verify_caci_uvm_endorsement(uvm_bytes, uvm_len, trusted_didx509,
                                 trusted_didx509_len, &uvm);

TavByteBuffer *report_data = NULL;
TavError *error = tav_verify_caci_attestation(
    attestation,
    minimum_tcb_cpuids, minimum_tcb_values, minimum_tcb_count,
    trusted_policy_digests, trusted_policy_digest_count,
    uvm, uvm_feed, uvm_feed_len, minimum_svn,
    &report_data);

tav_cbor_value_free(uvm);
tav_snp_attestation_report_free(attestation);
```

`report_data` is the verified 64-byte SNP `REPORT_DATA`; read it with
`tav_byte_buffer_data`/`tav_byte_buffer_len` and release it with
`tav_byte_buffer_free`. See `ffi/tests/c-consumer/caci.cpp` for the failure
modes and full error handling.
