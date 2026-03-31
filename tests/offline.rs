// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[path = "support/utils.rs"]
mod utils;
use tee_attestation_verification_lib::snp::verify::ChainVerification;
use tee_attestation_verification_lib::{certificate_from_pem, AttestationReport};
use zerocopy::FromBytes;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_node_experimental);

macro_rules! attestation_tests {
    ($milan_ask:expr, $genoa_ask:expr, $turin_ask:expr, $tampered_milan_attestation:expr) => {
        [
            (
                "genoa_ok_pinned",
                utils::GENOA_ATTESTATION,
                utils::GENOA_VCEK,
                ChainVerification::WithPinnedArk { ask: &$genoa_ask },
                Ok(()),
            ),
            (
                "turin_ok_pinned",
                utils::TURIN_ATTESTATION,
                utils::TURIN_VCEK,
                ChainVerification::WithPinnedArk { ask: &$turin_ask },
                Ok(()),
            ),
            (
                "milan_ok_pinned",
                utils::MILAN_ATTESTATION,
                utils::MILAN_VCEK,
                ChainVerification::WithPinnedArk { ask: &$milan_ask },
                Ok(()),
            ),
            (
                "milan_invalid_root_certificate",
                utils::MILAN_ATTESTATION,
                utils::MILAN_VCEK,
                ChainVerification::WithProvidedArk {
                    ask: &$milan_ask,
                    ark: &$milan_ask,
                },
                Err("Invalid root certificate"),
            ),
            (
                "milan_genoa_ask",
                utils::MILAN_ATTESTATION,
                utils::MILAN_VCEK,
                ChainVerification::WithPinnedArk { ask: &$genoa_ask },
                Err("Certificate chain error"),
            ),
            (
                "tampered_attestation",
                &$tampered_milan_attestation,
                utils::MILAN_VCEK,
                ChainVerification::Skip,
                Err("Signature verification error"),
            ),
        ]
    };
}

#[cfg(sync_crypto)]
mod sync {
    use super::*;

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_suite() {
        utils::init_logger();

        let tampered_milan_attestation = utils::tampered_attestation(utils::MILAN_ATTESTATION);
        let milan_ask = certificate_from_pem(utils::MILAN_ASK).unwrap();
        let genoa_ask = certificate_from_pem(utils::GENOA_ASK).unwrap();
        let turin_ask = certificate_from_pem(utils::TURIN_ASK).unwrap();

        for (tag, att, vcek, chain, expected) in
            attestation_tests!(milan_ask, genoa_ask, turin_ask, tampered_milan_attestation)
        {
            let report = AttestationReport::read_from_bytes(att).unwrap();
            let vcek = certificate_from_pem(vcek).unwrap();
            let result = tee_attestation_verification_lib::snp::verify::sync::verify_attestation(
                &report, &vcek, &chain,
            );

            if let Err(expected_error) = expected {
                let err = result.expect_err(&format!(
                    "{}: Expected to fail with {}",
                    tag, expected_error
                ));
                assert!(
                    err.to_string().contains(expected_error),
                    "{}: Expected error to contain '{}', got: {:?}",
                    tag,
                    expected_error,
                    err
                );
            } else {
                result.expect(&format!("{}: Expected verification to succeed", tag));
            }
        }
    }
}

#[cfg(async_crypto)]
mod asynchronous {
    use super::*;

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn test_suite() {
        utils::init_logger();

        let tampered_milan_attestation = utils::tampered_attestation(utils::MILAN_ATTESTATION);
        let milan_ask = certificate_from_pem(utils::MILAN_ASK).unwrap();
        let genoa_ask = certificate_from_pem(utils::GENOA_ASK).unwrap();
        let turin_ask = certificate_from_pem(utils::TURIN_ASK).unwrap();

        for (tag, att, vcek, chain, expected) in
            attestation_tests!(milan_ask, genoa_ask, turin_ask, tampered_milan_attestation)
        {
            let report = AttestationReport::read_from_bytes(att).unwrap();
            let vcek = certificate_from_pem(vcek).unwrap();
            let result =
                tee_attestation_verification_lib::snp::verify::asynchronous::verify_attestation(
                    &report, &vcek, &chain,
                )
                .await;

            if let Err(expected_error) = expected {
                let err = result.expect_err(&format!(
                    "{}: Expected to fail with {}",
                    tag, expected_error
                ));
                assert!(
                    err.to_string().contains(expected_error),
                    "{}: Expected error to contain '{}', got: {:?}",
                    tag,
                    expected_error,
                    err
                );
            } else {
                result.expect(&format!("{}: Expected verification to succeed", tag));
            }
        }
    }
}
