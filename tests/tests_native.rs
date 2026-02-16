// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Once;

mod common;

static INIT: Once = Once::new();

pub fn init_logger() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .is_test(true)
            .init();
    });
}

/// Online verification tests (async, fetches certs from AMD KDS)
#[cfg(feature = "online")]
mod online {
    use super::*;

    #[tokio::test]
    async fn test_verify_milan_attestation() {
        init_logger();
        let result = common::verify_milan_attestation()
            .await
            .expect("Verification call failed");

        assert!(
            result.is_valid,
            "Verification should pass: {:?}",
            result.errors
        );
    }

    #[tokio::test]
    async fn test_verify_genoa_attestation() {
        init_logger();
        let result = common::verify_genoa_attestation()
            .await
            .expect("Verification call failed");

        assert!(
            result.is_valid,
            "Verification should pass: {:?}",
            result.errors
        );
    }

    #[tokio::test]
    async fn test_verify_turin_attestation() {
        init_logger();
        let result = common::verify_turin_attestation()
            .await
            .expect("Verification call failed");

        assert!(
            result.is_valid,
            "Verification should pass: {:?}",
            result.errors
        );
    }
}

/// Offline verification tests (sync, uses pinned ARKs)
mod offline {
    use tee_attestation_verification_lib::snp;

    use super::*;

    #[test]
    fn test_verify_milan_attestation() {
        init_logger();
        let result =
            common::verify_milan_attestation_offline().expect("Offline verification call failed");

        assert!(
            result.is_valid,
            "Offline verification should pass: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_verify_genoa_attestation() {
        init_logger();
        let result =
            common::verify_genoa_attestation_offline().expect("Offline verification call failed");

        assert!(
            result.is_valid,
            "Offline verification should pass: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_verify_turin_attestation() {
        init_logger();
        let result =
            common::verify_turin_attestation_offline().expect("Offline verification call failed");

        assert!(
            result.is_valid,
            "Offline verification should pass: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_verify_offline_attestation_ffi() {
        init_logger();
        let tests = [
            (
                "Milan",
                common::MILAN_ATTESTATION,
                snp::root_certs::MILAN_ARK,
                common::MILAN_ASK,
                common::MILAN_VCEK,
            ),
            (
                "Genoa",
                common::GENOA_ATTESTATION,
                snp::root_certs::GENOA_ARK,
                common::GENOA_ASK,
                common::GENOA_VCEK,
            ),
            (
                "Turin",
                common::TURIN_ATTESTATION,
                snp::root_certs::TURIN_ARK,
                common::TURIN_ASK,
                common::TURIN_VCEK,
            ),
        ];
        for (name, attestation, ark, ask, vcek) in tests {
            common::verify_offline_snp_ffi(attestation, ark, ask, vcek)
                .expect(&format!("Offline FFI verification failed for {}", name));
        }
    }

    #[test]
    fn test_verify_offline_attestation_ffi_invalid_ark() {
        init_logger();
        common::verify_offline_snp_ffi(
            common::MILAN_ATTESTATION,
            snp::root_certs::GENOA_ARK, // Wrong ARK
            common::MILAN_ASK,
            common::MILAN_VCEK,
        )
        .expect_err("Verification should fail with wrong ARK");
    }
}
