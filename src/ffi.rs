// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C FFI bindings for TEE attestation verification.
//!
//! Errors are returned as an opaque `TAVError` pointer (NULL means success).
//! Use [`tav_error_code`] to get the error category, [`tav_error_message`] to
//! get a human-readable description, and [`tav_free_error`] to release it.
//! When passing an error output parameter, callers must either pass `NULL` or a
//! pointer to a `NULL` `TAVError*` slot.

use std::ffi::CString;
use std::os::raw::c_char;
use std::slice;

use zerocopy::FromBytes;

use crate::crypto::{Certificate, Crypto, CryptoBackend};
use crate::snp::report::{AttestationReport, SigningKey};
use crate::snp::verify::{self, ChainVerification, VerificationError};

// ---------------------------------------------------------------------------
// Error code enum
// ---------------------------------------------------------------------------

/// Error categories exposed over FFI.
///
/// Numbering convention:
/// - [1]: FFI/input parsing failures
/// - [101:105]: attestation verification failures (mapped from SevVerificationError)
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum TAVErrorCode {
    /// Invalid arguments passed to the function (bad report, bad PEM, etc.).
    InvalidArgument = 1,
    /// Invalid argument when retrieving an error message (e.g., null pointer).
    /// Note: this will never be returned otherwise
    ErrorCodeIsNull = 2,
    /// Processor model is unsupported.
    UnsupportedProcessor = 101,
    /// The provided ARK does not match the pinned root certificate.
    InvalidRootCertificate = 102,
    /// Certificate chain verification failed (ARK -> ASK -> VCEK).
    CertificateChainError = 103,
    /// Attestation report signature verification failed.
    SignatureVerificationError = 104,
    /// TCB values in certificate do not match the report.
    TcbVerificationError = 105,
}

/// Structured, heap-allocated error returned across FFI.
pub struct TAVError {
    code: TAVErrorCode,
    message: CString,
}

impl TAVError {
    fn new(code: TAVErrorCode, msg: String) -> Self {
        Self {
            code,
            message: CString::new(msg).unwrap_or_default(),
        }
    }

    fn invalid_argument(msg: String) -> Self {
        Self::new(TAVErrorCode::InvalidArgument, msg)
    }
}

impl From<VerificationError> for TAVError {
    fn from(e: VerificationError) -> Self {
        let code = match &e {
            VerificationError::UnsupportedProcessor(_) => TAVErrorCode::UnsupportedProcessor,
            VerificationError::InvalidRootCertificate(_) => TAVErrorCode::InvalidRootCertificate,
            VerificationError::CertificateChainError(_) => TAVErrorCode::CertificateChainError,
            VerificationError::SignatureVerificationError(_) => {
                TAVErrorCode::SignatureVerificationError
            }
            VerificationError::TcbVerificationError(_) => TAVErrorCode::TcbVerificationError,
        };
        Self::new(code, e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Opaque report handle
// ---------------------------------------------------------------------------

/// Opaque handle to a verified SNP attestation report.
///
/// Returned by [`tav_snp_verify_attestation`].  Must be freed with
/// [`tav_free_report`].
pub struct TAVSNPAttestationReport {
    report: *const AttestationReport,
}

impl TAVSNPAttestationReport {
    fn new(report: *const AttestationReport) -> Self {
        Self { report }
    }

    unsafe fn report(&self) -> &AttestationReport {
        &*self.report
    }
}

/// If `out` is non-null, write `err` through it and return `null`.
unsafe fn set_error(out: *mut *mut TAVError, err: TAVError) -> *mut TAVSNPAttestationReport {
    if !out.is_null() {
        *out = Box::into_raw(Box::new(err));
    }
    std::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// Error accessors
// ---------------------------------------------------------------------------

/// Get the error code from an error handle.
///
/// # Safety
/// `err` may be NULL. If NULL, returns [`TAVErrorCode::ErrorCodeIsNull`].
#[no_mangle]
pub unsafe extern "C" fn tav_error_code(err: *const TAVError) -> TAVErrorCode {
    if err.is_null() {
        TAVErrorCode::ErrorCodeIsNull
    } else {
        (*err).code
    }
}

/// Get a NUL-terminated error message from an error handle.
///
/// The returned pointer is valid until [`tav_free_error`] is called on this
/// error.  Do **not** free the returned string.
///
/// # Safety
/// `err` may be NULL. If NULL, returns a static fallback error message.
#[no_mangle]
pub unsafe extern "C" fn tav_error_message(err: *const TAVError) -> *const c_char {
    if err.is_null() {
        b"null TAVError pointer\0".as_ptr() as *const c_char
    } else {
        (*err).message.as_ptr()
    }
}

/// Free an error previously returned by [`tav_snp_verify_attestation`].
///
/// Safe to call with NULL (no-op).
///
/// # Safety
/// `err` must be a pointer returned by [`tav_snp_verify_attestation`], or NULL.
#[no_mangle]
pub unsafe extern "C" fn tav_free_error(err: *mut TAVError) {
    if !err.is_null() {
        drop(Box::from_raw(err));
    }
}

// ---------------------------------------------------------------------------
// Input parsing helpers
// ---------------------------------------------------------------------------

fn parse_report<'a>(bytes: &'a [u8]) -> Result<&'a AttestationReport, TAVError> {
    AttestationReport::ref_from_bytes(bytes).map_err(|_| {
        TAVError::invalid_argument(format!(
            "Invalid attestation report: expected {} bytes, got {}",
            std::mem::size_of::<AttestationReport>(),
            bytes.len(),
        ))
    })
}

fn parse_pem(name: &str, pem: &[u8]) -> Result<Certificate, TAVError> {
    Crypto::from_pem(pem)
        .map_err(|e| TAVError::invalid_argument(format!("Failed to parse {name} PEM: {e}")))
}

// ---------------------------------------------------------------------------
// Verification entry point
// ---------------------------------------------------------------------------

/// Verify an SEV-SNP attestation report using caller-provided ARK, ASK, and
/// VCEK certificates (all PEM-encoded).
///
/// # Returns
/// On success, returns an opaque handle that borrows the attestation report
/// bytes from `report_ptr`. The caller must keep `report_ptr` alive and
/// unchanged for as long as the returned handle is used.
///
/// On failure, returns `NULL`. If `err_out` is non-null and `*err_out` is NULL
/// on entry, sets `*err_out` to an opaque error handle. Use
/// [`tav_error_code`], [`tav_error_message`], and [`tav_free_error`] to inspect
/// and release the error.
///
/// # Safety
/// All pointer/length pairs must be valid readable memory.
/// `err_out` may be NULL if the caller does not need detailed error
/// information. If non-null, `*err_out` must be NULL on entry. Passing a
/// non-null `err_out` whose pointee is already non-null is an invalid argument.
/// On success, `*err_out` remains NULL. On failure, `*err_out` is set to an
/// allocated [`TAVError`] only when it was NULL on entry; otherwise it is left
/// unchanged.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_verify_attestation(
    report_ptr: *const u8,
    report_len: usize,
    ark_pem_ptr: *const u8,
    ark_pem_len: usize,
    ask_pem_ptr: *const u8,
    ask_pem_len: usize,
    vcek_pem_ptr: *const u8,
    vcek_pem_len: usize,
    err_out: *mut *mut TAVError,
) -> *mut TAVSNPAttestationReport {
    if !err_out.is_null() {
        if !(*err_out).is_null() {
            return std::ptr::null_mut();
        }

        *err_out = std::ptr::null_mut();
    }

    let inner = || -> Result<*const AttestationReport, TAVError> {
        let report_bytes = slice::from_raw_parts(report_ptr, report_len);
        let report = parse_report(report_bytes)?;
        let ark = parse_pem("ARK", slice::from_raw_parts(ark_pem_ptr, ark_pem_len))?;
        let ask = parse_pem("ASK", slice::from_raw_parts(ask_pem_ptr, ask_pem_len))?;
        let vcek = parse_pem("VCEK", slice::from_raw_parts(vcek_pem_ptr, vcek_pem_len))?;
        verify::verify_attestation(
            report,
            &vcek,
            ChainVerification::WithProvidedArk {
                ask: &ask,
                ark: &ark,
            },
        )
        .map_err(TAVError::from)?;
        Ok(report as *const AttestationReport)
    };

    match inner() {
        Ok(report) => Box::into_raw(Box::new(TAVSNPAttestationReport::new(report))),
        Err(e) => set_error(err_out, e),
    }
}

// ---------------------------------------------------------------------------
// Report lifecycle
// ---------------------------------------------------------------------------

/// Free a report previously returned by [`tav_snp_verify_attestation`].
///
/// Safe to call with NULL (no-op).
///
/// # Safety
/// `report` must be a pointer returned by [`tav_snp_verify_attestation`], or NULL.
#[no_mangle]
pub unsafe extern "C" fn tav_free_report(report: *mut TAVSNPAttestationReport) {
    if !report.is_null() {
        drop(Box::from_raw(report));
    }
}

// ---------------------------------------------------------------------------
// Report accessor functions – scalar fields
// ---------------------------------------------------------------------------
//
// Multi-byte integers are converted from the on-wire little-endian format to
// the platform's native byte order.
//
// Safety: `report` must be a non-null pointer returned by
// [`tav_snp_verify_attestation`]. Because the handle borrows from the caller's
// report buffer, that input buffer must remain alive and unchanged until
// [`tav_free_report`] is called.

/// Get the attestation report version.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_version(report: *const TAVSNPAttestationReport) -> u32 {
    (*report).report().version.get()
}

/// Get the guest SVN (Security Version Number).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_guest_svn(report: *const TAVSNPAttestationReport) -> u32 {
    (*report).report().guest_svn.get()
}

/// Get the guest policy.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_policy(report: *const TAVSNPAttestationReport) -> u64 {
    (*report).report().policy.get()
}

/// Get the minimum ABI minor version required by the guest policy.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_policy_abi_minor(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().policy().abi_minor()
}

/// Get the minimum ABI major version required by the guest policy.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_policy_abi_major(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().policy().abi_major()
}

/// Get whether SMT is allowed by the guest policy.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_policy_smt(report: *const TAVSNPAttestationReport) -> u8 {
    (*report).report().policy().smt().into()
}

/// Get whether migration-agent association is allowed by the guest policy.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_policy_migrate_ma(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().policy().migrate_ma().into()
}

/// Get whether debugging is allowed by the guest policy.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_policy_debug(report: *const TAVSNPAttestationReport) -> u8 {
    (*report).report().policy().debug().into()
}

/// Get whether the guest is restricted to a single socket.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_policy_single_socket(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().policy().single_socket().into()
}

/// Get whether CXL population with devices or memory is allowed.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_policy_cxl_allow(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().policy().cxl_allow().into()
}

/// Get whether AES-256-XTS is required for memory encryption.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_policy_mem_aes_256_xts(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().policy().mem_aes_256_xts().into()
}

/// Get whether the RAPL feature is disabled by the guest policy.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_policy_rapl_dis(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().policy().rapl_dis().into()
}

/// Get whether DRAM ciphertext hiding must be enabled.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_policy_ciphertext_hiding_dram(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().policy().ciphertext_hiding_dram().into()
}

/// Get whether guest access to page move commands is disabled.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_policy_page_swap_disable(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().policy().page_swap_disable().into()
}

/// Get the VMPL for this report.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_vmpl(report: *const TAVSNPAttestationReport) -> u32 {
    (*report).report().vmpl.get()
}

/// Get the signature algorithm used to sign this report.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_signature_algo(
    report: *const TAVSNPAttestationReport,
) -> u32 {
    (*report).report().signature_algo.get()
}

/// Get platform info flags.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_platform_info(
    report: *const TAVSNPAttestationReport,
) -> u64 {
    (*report).report().platform_info.get()
}

/// Get the flags field.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_flags(report: *const TAVSNPAttestationReport) -> u32 {
    (*report).report().flags.get()
}

/// Get the raw AUTHOR_KEY_EN flag bit.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_flags_author_key_en(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().flags().author_key_en().into()
}

/// Get whether the chip ID is masked.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_flags_mask_chip_key(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().flags().mask_chip_key().into()
}

/// Get the raw signing-key selector from the report flags.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_flags_signing_key(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    match (*report).report().flags().signing_key() {
        SigningKey::Vcek => 0,
        SigningKey::Vlek => 1,
        SigningKey::None => 7,
        SigningKey::Reserved(value) => value,
    }
}

// ---------------------------------------------------------------------------
// Report accessor functions – single-byte fields
// ---------------------------------------------------------------------------

/// Get the CPUID Family ID.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_cpuid_fam_id(report: *const TAVSNPAttestationReport) -> u8 {
    (*report).report().cpuid_fam_id
}

/// Get the CPUID Model ID.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_cpuid_mod_id(report: *const TAVSNPAttestationReport) -> u8 {
    (*report).report().cpuid_mod_id
}

/// Get the CPUID Stepping.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_cpuid_step(report: *const TAVSNPAttestationReport) -> u8 {
    (*report).report().cpuid_step
}

/// Get the build number of CurrentVersion.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_current_build(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().current_build
}

/// Get the minor number of CurrentVersion.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_current_minor(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().current_minor
}

/// Get the major number of CurrentVersion.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_current_major(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().current_major
}

/// Get the build number of CommittedVersion.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_committed_build(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().committed_build
}

/// Get the minor number of CommittedVersion.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_committed_minor(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().committed_minor
}

/// Get the major number of CommittedVersion.
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_committed_major(
    report: *const TAVSNPAttestationReport,
) -> u8 {
    (*report).report().committed_major
}

// ---------------------------------------------------------------------------
// Report accessor functions – byte-array fields
// ---------------------------------------------------------------------------
//
// Returned pointers borrow from the report handle and are valid until
// [`tav_free_report`] is called.

/// Get the family ID (16 bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_family_id(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().family_id.as_ptr()
}

/// Get the image ID (16 bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_image_id(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().image_id.as_ptr()
}

/// Get the platform TCB version (8 raw bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_platform_version(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().platform_version.raw.as_ptr()
}

/// Get the guest-provided report data (64 bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_report_data(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().report_data.as_ptr()
}

/// Get the launch measurement (48 bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_measurement(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().measurement.as_ptr()
}

/// Get the host data (32 bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_host_data(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().host_data.as_ptr()
}

/// Get the ID key digest (48 bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_id_key_digest(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().id_key_digest.as_ptr()
}

/// Get the author key digest (48 bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_author_key_digest(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().author_key_digest.as_ptr()
}

/// Get the report ID (32 bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_report_id(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().report_id.as_ptr()
}

/// Get the report ID of the migration agent (32 bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_report_id_ma(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().report_id_ma.as_ptr()
}

/// Get the reported TCB version (8 raw bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_reported_tcb(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().reported_tcb.raw.as_ptr()
}

/// Get the chip ID (64 bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_chip_id(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().chip_id.as_ptr()
}

/// Get the committed TCB version (8 raw bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_committed_tcb(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().committed_tcb.raw.as_ptr()
}

/// Get the launch TCB version (8 raw bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_launch_tcb(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().launch_tcb.raw.as_ptr()
}

/// Get the signature R component (72 bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_signature_r(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().signature.r.as_ptr()
}

/// Get the signature S component (72 bytes).
#[no_mangle]
pub unsafe extern "C" fn tav_snp_report_signature_s(
    report: *const TAVSNPAttestationReport,
) -> *const u8 {
    (*report).report().signature.s.as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::ptr;

    const MILAN_ATTESTATION: &[u8] =
        include_bytes!("../tests/test_data/milan_attestation_report.bin");
    const MILAN_ASK: &[u8] = include_bytes!("../tests/test_data/milan_ask.pem");
    const MILAN_VCEK: &[u8] = include_bytes!("../tests/test_data/milan_vcek.pem");
    const MILAN_ARK: &[u8] = include_bytes!("pinned_arks/milan_ark.pem");

    fn verify_with_err_out(err_out: *mut *mut TAVError) -> *mut TAVSNPAttestationReport {
        unsafe {
            tav_snp_verify_attestation(
                MILAN_ATTESTATION.as_ptr(),
                MILAN_ATTESTATION.len(),
                MILAN_ARK.as_ptr(),
                MILAN_ARK.len(),
                MILAN_ASK.as_ptr(),
                MILAN_ASK.len(),
                MILAN_VCEK.as_ptr(),
                MILAN_VCEK.len(),
                err_out,
            )
        }
    }

    #[test]
    fn ffi_accepts_null_err_out() {
        let report = verify_with_err_out(ptr::null_mut());

        assert!(!report.is_null());

        unsafe {
            tav_free_report(report);
        }
    }

    #[test]
    fn ffi_writes_error_when_err_out_points_to_null() {
        let mut error = ptr::null_mut();
        let report = unsafe {
            tav_snp_verify_attestation(
                MILAN_ATTESTATION.as_ptr(),
                MILAN_ATTESTATION.len(),
                MILAN_ASK.as_ptr(),
                MILAN_ASK.len(),
                MILAN_ASK.as_ptr(),
                MILAN_ASK.len(),
                MILAN_VCEK.as_ptr(),
                MILAN_VCEK.len(),
                &mut error,
            )
        };

        assert!(report.is_null());
        assert!(!error.is_null());

        unsafe {
            assert_eq!(
                tav_error_code(error) as u32,
                TAVErrorCode::InvalidRootCertificate as u32
            );
            assert!(CStr::from_ptr(tav_error_message(error))
                .to_str()
                .unwrap()
                .contains("Invalid root certificate"));
            tav_free_error(error);
        }
    }

    #[test]
    fn ffi_rejects_non_null_err_out_pointee_without_overwriting_it() {
        let sentinel = Box::into_raw(Box::new([0xAB_u8; 8])) as *mut TAVError;
        let mut error = sentinel;

        let report = verify_with_err_out(&mut error);

        assert!(report.is_null());
        assert_eq!(error, sentinel);

        unsafe {
            drop(Box::from_raw(sentinel as *mut [u8; 8]));
        }
    }
}
