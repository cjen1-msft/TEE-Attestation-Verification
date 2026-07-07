//! `wasm_bindgen` bindings exposing verified SNP attestation reports to JS.
//!
//! SnpAttestationReport is opaque and can only be obtained through successful
//! verification with `verify_attestation_async`. Its accessor methods return
//! fields from the verified report bytes.
//!
//! See `demos/web-verify-kernel/README.md` in the repository for a runnable
//! browser demo that uses these bindings.

use js_sys::Array;
use wasm_bindgen::prelude::*;
use zerocopy::{FromBytes, IntoBytes};

use crate::wasm_ffi::utils::VerifyError;
use attestation::snp::report::AttestationReport;
use attestation::snp::verify::ChainVerification;
use crypto::{Certificate, CertificateBackend, Crypto};

/// A cryptographically verified SEV-SNP attestation report.
///
/// Obtained from [`verify_attestation_async`]. Accessor methods return
/// fields from the verified report bytes.
#[wasm_bindgen]
#[derive(Debug)]
pub struct SnpAttestationReport {
    bytes: Vec<u8>,
}

/// Verify an SEV-SNP attestation report.
///
/// Takes ownership of `report_bytes`. Parses PEM-encoded ARK, ASK, and
/// VCEK certificates, verifies the full certificate chain and report
/// signature, and on success returns a [`SnpAttestationReport`] wrapping
/// the verified bytes.
#[wasm_bindgen]
#[cfg(async_crypto)]
pub async fn verify_attestation_async(
    report_bytes: Vec<u8>,
    ark_pem: &str,
    ask_pem: &str,
    vcek_pem: &str,
) -> Result<SnpAttestationReport, VerifyError> {
    // Parse: report length check + PEM parses (all produce InvalidArgument).
    parse_report(&report_bytes)?;
    let ark = parse_pem("ARK", ark_pem)?;
    let ask = parse_pem("ASK", ask_pem)?;
    let vcek = parse_pem("VCEK", vcek_pem)?;

    // Re-borrow the report for verification (ref_from_bytes is zero-copy
    // and we've already validated the length above).
    let report = parse_report(&report_bytes)?;

    attestation::snp::verify::asynchronous::verify_attestation(
        report,
        &vcek,
        &ChainVerification::WithProvidedArk {
            ask: &ask,
            ark: &ark,
        },
    )
    .await
    .map_err(VerifyError::from)?;

    Ok(SnpAttestationReport {
        bytes: report_bytes,
    })
}

/// Split a PEM certificate bundle into individual PEM certificates.
///
/// Parses the bundle with the active crypto backend and returns certificates
/// in the same order they appeared in the input.
#[wasm_bindgen]
pub fn split_certificate_bundle(pem_bundle: &str) -> Result<Array, String> {
    if pem_bundle.trim().is_empty() {
        return Err("Certificate bundle PEM is empty".into());
    }

    let certificates = Crypto::from_pem_chain(pem_bundle.as_bytes())
        .map_err(|e| format!("Failed to parse certificate bundle PEM: {e}"))?;

    let split = Array::new();
    for certificate in certificates {
        let pem = Crypto::to_pem(&certificate)
            .map_err(|e| format!("Failed to encode certificate PEM: {e}"))?;
        split.push(&JsValue::from_str(&pem));
    }

    Ok(split)
}

fn parse_report(bytes: &[u8]) -> Result<&AttestationReport, VerifyError> {
    AttestationReport::ref_from_bytes(bytes).map_err(|_| {
        VerifyError::invalid_argument(format!(
            "Invalid attestation report: expected {} bytes, got {}",
            std::mem::size_of::<AttestationReport>(),
            bytes.len(),
        ))
    })
}

fn parse_pem(name: &str, pem: &str) -> Result<Certificate, VerifyError> {
    Crypto::from_pem(pem.as_bytes())
        .map_err(|e| VerifyError::invalid_argument(format!("Failed to parse {name} PEM: {e}")))
}

// -----------------------------------------------------------------------
// Accessor methods
//
// Each method re-parses `self.bytes` via zero-copy `ref_from_bytes`. The
// struct's invariants (verified length at construction) make this
// infallible, so we `.expect()` on the parse.
// -----------------------------------------------------------------------

impl SnpAttestationReport {
    pub fn from_verified_report(report: AttestationReport) -> Self {
        Self {
            bytes: report.as_bytes().to_vec(),
        }
    }

    pub fn report(&self) -> &AttestationReport {
        AttestationReport::ref_from_bytes(&self.bytes)
            .expect("SnpAttestationReport is only constructed from verified bytes so this parse should not fail")
    }
}

#[wasm_bindgen]
impl SnpAttestationReport {
    // -- Scalar fields --

    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u32 {
        self.report().version.get()
    }

    #[wasm_bindgen(getter)]
    pub fn guest_svn(&self) -> u32 {
        self.report().guest_svn.get()
    }

    #[wasm_bindgen(getter)]
    pub fn policy(&self) -> u64 {
        self.report().policy.get()
    }

    #[wasm_bindgen(getter)]
    pub fn policy_abi_minor(&self) -> u8 {
        self.report().policy().abi_minor()
    }

    #[wasm_bindgen(getter)]
    pub fn policy_abi_major(&self) -> u8 {
        self.report().policy().abi_major()
    }

    #[wasm_bindgen(getter)]
    pub fn policy_smt(&self) -> bool {
        self.report().policy().smt()
    }

    #[wasm_bindgen(getter)]
    pub fn policy_migrate_ma(&self) -> bool {
        self.report().policy().migrate_ma()
    }

    #[wasm_bindgen(getter)]
    pub fn policy_debug(&self) -> bool {
        self.report().policy().debug()
    }

    #[wasm_bindgen(getter)]
    pub fn policy_single_socket(&self) -> bool {
        self.report().policy().single_socket()
    }

    #[wasm_bindgen(getter)]
    pub fn policy_cxl_allow(&self) -> bool {
        self.report().policy().cxl_allow()
    }

    #[wasm_bindgen(getter)]
    pub fn policy_mem_aes_256_xts(&self) -> bool {
        self.report().policy().mem_aes_256_xts()
    }

    #[wasm_bindgen(getter)]
    pub fn policy_rapl_dis(&self) -> bool {
        self.report().policy().rapl_dis()
    }

    #[wasm_bindgen(getter)]
    pub fn policy_ciphertext_hiding_dram(&self) -> bool {
        self.report().policy().ciphertext_hiding_dram()
    }

    #[wasm_bindgen(getter)]
    pub fn policy_page_swap_disable(&self) -> bool {
        self.report().policy().page_swap_disable()
    }

    #[wasm_bindgen(getter)]
    pub fn vmpl(&self) -> u32 {
        self.report().vmpl.get()
    }

    #[wasm_bindgen(getter)]
    pub fn signature_algo(&self) -> u32 {
        self.report().signature_algo.get()
    }

    #[wasm_bindgen(getter)]
    pub fn platform_info(&self) -> u64 {
        self.report().platform_info.get()
    }

    #[wasm_bindgen(getter)]
    pub fn flags(&self) -> u32 {
        self.report().flags.get()
    }

    #[wasm_bindgen(getter)]
    pub fn flags_author_key_en(&self) -> bool {
        self.report().flags().author_key_en()
    }

    #[wasm_bindgen(getter)]
    pub fn flags_mask_chip_key(&self) -> bool {
        self.report().flags().mask_chip_key()
    }

    #[wasm_bindgen(getter)]
    pub fn flags_signing_key(&self) -> u8 {
        self.report().flags().signing_key().raw()
    }

    // -- Single-byte fields --

    #[wasm_bindgen(getter)]
    pub fn cpuid_fam_id(&self) -> u8 {
        self.report().cpuid_fam_id
    }

    #[wasm_bindgen(getter)]
    pub fn cpuid_mod_id(&self) -> u8 {
        self.report().cpuid_mod_id
    }

    #[wasm_bindgen(getter)]
    pub fn cpuid_step(&self) -> u8 {
        self.report().cpuid_step
    }

    #[wasm_bindgen(getter)]
    pub fn current_build(&self) -> u8 {
        self.report().current_build
    }

    #[wasm_bindgen(getter)]
    pub fn current_minor(&self) -> u8 {
        self.report().current_minor
    }

    #[wasm_bindgen(getter)]
    pub fn current_major(&self) -> u8 {
        self.report().current_major
    }

    #[wasm_bindgen(getter)]
    pub fn committed_build(&self) -> u8 {
        self.report().committed_build
    }

    #[wasm_bindgen(getter)]
    pub fn committed_minor(&self) -> u8 {
        self.report().committed_minor
    }

    #[wasm_bindgen(getter)]
    pub fn committed_major(&self) -> u8 {
        self.report().committed_major
    }

    // -- Byte-array fields (returned as Vec<u8>) --

    #[wasm_bindgen(getter)]
    pub fn family_id(&self) -> Vec<u8> {
        self.report().family_id.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn image_id(&self) -> Vec<u8> {
        self.report().image_id.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn platform_version(&self) -> Vec<u8> {
        self.report().platform_version.raw.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn report_data(&self) -> Vec<u8> {
        self.report().report_data.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn measurement(&self) -> Vec<u8> {
        self.report().measurement.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn host_data(&self) -> Vec<u8> {
        self.report().host_data.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn id_key_digest(&self) -> Vec<u8> {
        self.report().id_key_digest.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn author_key_digest(&self) -> Vec<u8> {
        self.report().author_key_digest.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn report_id(&self) -> Vec<u8> {
        self.report().report_id.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn report_id_ma(&self) -> Vec<u8> {
        self.report().report_id_ma.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn reported_tcb(&self) -> Vec<u8> {
        self.report().reported_tcb.raw.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn chip_id(&self) -> Vec<u8> {
        self.report().chip_id.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn committed_tcb(&self) -> Vec<u8> {
        self.report().committed_tcb.raw.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn launch_tcb(&self) -> Vec<u8> {
        self.report().launch_tcb.raw.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn signature_r(&self) -> Vec<u8> {
        self.report().signature.r.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn signature_s(&self) -> Vec<u8> {
        self.report().signature.s.to_vec()
    }
}

#[cfg(test)]
mod split_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    const MILAN_ARK: &str = include_str!("../../../attestation/src/pinned_arks/milan_ark.pem");
    const MILAN_ASK: &str = include_str!("../../../attestation/tests/test_data/milan_ask.pem");

    #[wasm_bindgen_test]
    fn split_certificate_bundle_returns_pem_certificates_in_order() {
        let bundle = format!("{MILAN_ASK}\n{MILAN_ARK}");

        let split = split_certificate_bundle(&bundle).expect("bundle should split");

        assert_eq!(split.length(), 2);
        assert_certificate_matches_pem(&split, 0, MILAN_ASK);
        assert_certificate_matches_pem(&split, 1, MILAN_ARK);
    }

    #[wasm_bindgen_test]
    fn split_certificate_bundle_rejects_empty_bundle() {
        let err = match split_certificate_bundle("") {
            Ok(_) => panic!("empty bundle should fail"),
            Err(err) => err,
        };

        assert!(err.contains("empty"));
    }

    #[wasm_bindgen_test]
    fn split_certificate_bundle_rejects_invalid_pem() {
        let err = match split_certificate_bundle("not a pem") {
            Ok(_) => panic!("invalid bundle should fail"),
            Err(err) => err,
        };

        assert!(err.contains("certificate bundle PEM"));
    }

    fn assert_certificate_matches_pem(split: &Array, index: u32, expected_pem: &str) {
        let actual_pem = split
            .get(index)
            .as_string()
            .expect("split certificate should be a PEM string");
        let actual =
            Crypto::from_pem(actual_pem.as_bytes()).expect("split certificate PEM should parse");
        let expected = Crypto::from_pem(expected_pem.as_bytes()).expect("fixture PEM should parse");

        assert_eq!(
            Crypto::to_der(&actual).expect("split certificate should encode as DER"),
            Crypto::to_der(&expected).expect("fixture certificate should encode as DER")
        );
    }
}

#[cfg(all(test, async_crypto))]
mod tests {
    use super::*;
    use crate::TavErrorCode;
    use wasm_bindgen_test::wasm_bindgen_test;

    const MILAN_REPORT: &[u8] =
        include_bytes!("../../../attestation/tests/test_data/milan_attestation_report.bin");
    const MILAN_ARK: &str = include_str!("../../../attestation/src/pinned_arks/milan_ark.pem");
    const MILAN_ASK: &str = include_str!("../../../attestation/tests/test_data/milan_ask.pem");
    const MILAN_VCEK: &str = include_str!("../../../attestation/tests/test_data/milan_vcek.pem");

    #[wasm_bindgen_test]
    async fn verify_valid_attestation_returns_report() {
        let report =
            verify_attestation_async(MILAN_REPORT.to_vec(), MILAN_ARK, MILAN_ASK, MILAN_VCEK)
                .await
                .expect("verify should succeed");

        // Sanity-check a few getters — versions and sizes should be as
        // expected for the Milan test fixture.
        // Milan fixture is a version-3 report.
        assert_eq!(report.version(), 3);
        assert_eq!(report.measurement().len(), 48);
        assert_eq!(report.report_data().len(), 64);
        assert_eq!(report.chip_id().len(), 64);
    }

    #[wasm_bindgen_test]
    async fn verify_rejects_empty_report() {
        let err = verify_attestation_async(Vec::new(), MILAN_ARK, MILAN_ASK, MILAN_VCEK)
            .await
            .expect_err("empty report should fail");
        assert_eq!(err.code(), TavErrorCode::InvalidArgument);
        assert!(err.message().contains("expected 1184 bytes, got 0"));
    }

    #[wasm_bindgen_test]
    async fn verify_rejects_truncated_report() {
        let err = verify_attestation_async(
            MILAN_REPORT[..100].to_vec(),
            MILAN_ARK,
            MILAN_ASK,
            MILAN_VCEK,
        )
        .await
        .expect_err("truncated report should fail");
        assert_eq!(err.code(), TavErrorCode::InvalidArgument);
    }

    #[wasm_bindgen_test]
    async fn verify_rejects_invalid_ark_pem() {
        let err =
            verify_attestation_async(MILAN_REPORT.to_vec(), "not a pem", MILAN_ASK, MILAN_VCEK)
                .await
                .expect_err("invalid ARK should fail");
        assert_eq!(err.code(), TavErrorCode::InvalidArgument);
        assert!(err.message().contains("ARK PEM"));
    }

    #[wasm_bindgen_test]
    async fn verify_rejects_invalid_ask_pem() {
        let err =
            verify_attestation_async(MILAN_REPORT.to_vec(), MILAN_ARK, "not a pem", MILAN_VCEK)
                .await
                .expect_err("invalid ASK should fail");
        assert_eq!(err.code(), TavErrorCode::InvalidArgument);
        assert!(err.message().contains("ASK PEM"));
    }

    #[wasm_bindgen_test]
    async fn verify_rejects_invalid_vcek_pem() {
        let err =
            verify_attestation_async(MILAN_REPORT.to_vec(), MILAN_ARK, MILAN_ASK, "not a pem")
                .await
                .expect_err("invalid VCEK should fail");
        assert_eq!(err.code(), TavErrorCode::InvalidArgument);
        assert!(err.message().contains("VCEK PEM"));
    }

    #[wasm_bindgen_test]
    async fn verify_rejects_wrong_ark() {
        // Use ASK in place of ARK — should fail root certificate validation.
        let err = verify_attestation_async(MILAN_REPORT.to_vec(), MILAN_ASK, MILAN_ASK, MILAN_VCEK)
            .await
            .expect_err("wrong ARK should fail");
        assert_eq!(err.code(), TavErrorCode::InvalidRootCertificate);
    }

    #[wasm_bindgen_test]
    async fn verify_rejects_corrupted_report_body() {
        let mut corrupted = MILAN_REPORT.to_vec();
        corrupted[100] ^= 0xFF;
        let err = verify_attestation_async(corrupted, MILAN_ARK, MILAN_ASK, MILAN_VCEK)
            .await
            .expect_err("corrupted report should fail");
        assert_eq!(err.code(), TavErrorCode::SignatureVerificationError);
    }
}
