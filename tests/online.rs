// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(all(any(target_arch = "wasm32", feature = "online"), async_crypto))]

#[path = "support/online.rs"]
mod online_support;
#[path = "support/utils.rs"]
mod utils;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_node_experimental);

macro_rules! online_attestation_test {
    ($name:ident, $verifier:ident) => {
        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn $name() {
            utils::init_logger();
            online_support::$verifier()
                .await
                .expect("Verification call failed");
        }
    };
}

online_attestation_test!(test_verify_milan_attestation, verify_milan_attestation);
online_attestation_test!(test_verify_genoa_attestation, verify_genoa_attestation);
online_attestation_test!(test_verify_turin_attestation, verify_turin_attestation);
