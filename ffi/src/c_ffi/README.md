# C ABI

Native C ABI for CBOR, SNP, COSE, and CACI verification. Headers live under
`ffi/include/tav/`; each header's usage summary documents its own surface in
more detail (`cbor.h`, `snp.h`, `cose.h`, `caci.h`, `utils.h`).

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

## Legacy COSE CBOR handle ownership

The `TavCborValue*` API in `tav/cose.h` remains separate and unchanged.
Do not mix it with `TavCborHandle*`, or interchange their kind constants.

Every CBOR parser, navigation, and COSE validation function returns an
independently owned `TavCborValue *`. Projected handles share the immutable
parsed document through reference counting; they do not clone a subtree or
serialize and reparse it. Free every returned handle with the null-safe
`tav_cbor_value_free`. Parent and child handles may be freed in any order:

```c
TavCborValue *root = NULL;
TavCborValue *child = NULL;
tav_cbor_value_from_bytes(cbor, cbor_len, &root);
tav_cbor_value_array_at(root, 0, &child);

tav_cbor_value_free(root); /* child remains valid */
TavCborKind kind = tav_cbor_value_kind(child);
tav_cbor_value_free(child);
```

Byte and text pointers are borrowed from the handle passed to their accessor and
remain valid until that handle is freed.

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
