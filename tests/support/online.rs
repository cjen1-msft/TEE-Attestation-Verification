// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::utils;
use tee_attestation_verification_lib::AttestationReport;
use tee_attestation_verification_lib::SevVerifier;
use zerocopy::FromBytes;

pub async fn verify_attestation_bytes(bytes: &[u8]) -> Result<(), String> {
    let attestation_report = AttestationReport::read_from_bytes(bytes)
        .map_err(|e| format!("Failed to read attestation report: {:?}", e))?;

    let mut verifier = SevVerifier::new()
        .await
        .map_err(|e| format!("Failed to initialize verifier: {:?}", e))?;

    verifier
        .verify_attestation(&attestation_report)
        .await
        .map_err(|e| format!("Verification call failed: {:?}", e))
}

pub async fn verify_milan_attestation() -> Result<(), String> {
    verify_attestation_bytes(utils::MILAN_ATTESTATION).await
}

pub async fn verify_genoa_attestation() -> Result<(), String> {
    verify_attestation_bytes(utils::GENOA_ATTESTATION).await
}

pub async fn verify_turin_attestation() -> Result<(), String> {
    verify_attestation_bytes(utils::TURIN_ATTESTATION).await
}
