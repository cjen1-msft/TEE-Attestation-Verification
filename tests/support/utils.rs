// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::sync::Once;

#[allow(dead_code)]
pub const MILAN_ATTESTATION: &[u8] = include_bytes!("../test_data/milan_attestation_report.bin");
#[allow(dead_code)]
pub const GENOA_ATTESTATION: &[u8] = include_bytes!("../test_data/genoa_attestation_report.bin");
#[allow(dead_code)]
pub const TURIN_ATTESTATION: &[u8] = include_bytes!("../test_data/turin_attestation_report.bin");

#[allow(dead_code)]
pub const MILAN_ASK: &[u8] = include_bytes!("../test_data/milan_ask.pem");
#[allow(dead_code)]
pub const GENOA_ASK: &[u8] = include_bytes!("../test_data/genoa_ask.pem");
#[allow(dead_code)]
pub const TURIN_ASK: &[u8] = include_bytes!("../test_data/turin_ask.pem");

#[allow(dead_code)]
pub const MILAN_VCEK: &[u8] = include_bytes!("../test_data/milan_vcek.pem");
#[allow(dead_code)]
pub const GENOA_VCEK: &[u8] = include_bytes!("../test_data/genoa_vcek.pem");
#[allow(dead_code)]
pub const TURIN_VCEK: &[u8] = include_bytes!("../test_data/turin_vcek.pem");

static INIT: Once = Once::new();

pub fn init_logger() {
    INIT.call_once(|| {
        #[cfg(target_arch = "wasm32")]
        {
            console_error_panic_hook::set_once();
            let level = option_env!("RUST_LOG")
                .and_then(|value| value.parse().ok())
                .unwrap_or(log::Level::Info);
            wasm_logger::init(wasm_logger::Config::new(level));
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                .is_test(true)
                .init();
        }
    });
}

#[allow(dead_code)]
pub fn tampered_attestation(bytes: &[u8]) -> Vec<u8> {
    let mut tampered = bytes.to_vec();
    tampered[100] ^= 0xFF;
    tampered
}
