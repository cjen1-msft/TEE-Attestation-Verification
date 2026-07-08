// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(not(feature = "kds"))]
compile_error!("kds module requires the 'kds' feature");

use crate::crypto::{Certificate, CertificateBackend, Crypto};
use crate::snp;
use crate::{certificate_chain::CertificateFetcher, AttestationReport};
#[cfg(target_arch = "wasm32")]
use js_sys::{Promise, Uint8Array};
use log::{debug, info};
use std::mem::discriminant;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;

/// Per-generation cache of AMD certificate chains (ARK and ASK).
///
/// Each processor generation has its own KDS certificate chain, so entries are
/// keyed by [`snp::model::Generation`] to avoid returning one generation's chain
/// for another.
type ChainCache = Vec<(snp::model::Generation, (Certificate, Certificate))>;

/// KDS (Key Distribution Service) certificate fetcher
/// Fetches certificates from AMD's public KDS service
pub(crate) struct KdsFetcher {
    chain_cache: ChainCache,
    vcek_cache: std::collections::HashMap<String, Certificate>,
    use_cache: bool,
}

impl KdsFetcher {
    pub(crate) fn new() -> Self {
        Self {
            chain_cache: Vec::new(),
            vcek_cache: std::collections::HashMap::new(),
            use_cache: false,
        }
    }

    pub(crate) fn with_cache() -> Self {
        Self {
            chain_cache: Vec::new(),
            vcek_cache: std::collections::HashMap::new(),
            use_cache: true,
        }
    }
}

impl CertificateFetcher for KdsFetcher {
    async fn fetch_amd_chain(
        &mut self,
        model: snp::model::Generation,
    ) -> Result<(Certificate, Certificate), Box<dyn std::error::Error>> {
        // Check cache for ARK/ASK for this processor generation
        if self.use_cache {
            if let Some((_, (ark, ask))) = self
                .chain_cache
                .iter()
                .find(|(gen, _)| discriminant(gen) == discriminant(&model))
            {
                info!("Using cached AMD certificate chain (ARK/ASK) for {}", model);
                return Ok((ark.clone(), ask.clone()));
            }
        }

        let cert_chain_url = format!("https://kdsintf.amd.com/vcek/v1/{}/cert_chain", model);
        let pem_bytes = fetch_url_bytes(&cert_chain_url).await?;
        let certs = Crypto::from_pem_chain(&pem_bytes)
            .map_err(|e| format!("Failed to parse PEM certificate chain: {}", e))?;
        if certs.len() != 2 {
            return Err("Certificate chain must contain exactly 2 certificates".into());
        }
        let ark = certs[1].clone();
        let ask = certs[0].clone();

        debug!(
            "Using {} ark pem:\n{}",
            model,
            Crypto::to_pem(&ark).map_err(|e| format!("Failed to encode ARK certificate: {}", e))?
        );
        debug!(
            "Using {} ask pem:\n{}",
            model,
            Crypto::to_pem(&ask).map_err(|e| format!("Failed to encode ASK certificate: {}", e))?
        );

        // Store in cache if requested, keyed by processor generation
        if self.use_cache {
            self.chain_cache.push((model, (ark.clone(), ask.clone())));
            info!("Cached AMD certificate chain (ARK/ASK) for {}", model);
        }

        Ok((ark, ask))
    }

    async fn fetch_amd_vcek(
        &mut self,
        processor_model: snp::model::Generation,
        attestation_report: &AttestationReport,
    ) -> Result<Certificate, Box<dyn std::error::Error>> {
        // Build a cache key using processor model and first 8 bytes of the chip id
        let cache_key = format!(
            "{}_{:02x?}",
            processor_model,
            &attestation_report.chip_id[..8]
        );

        if self.use_cache {
            if let Some(cached) = self.vcek_cache.get(&cache_key) {
                // Return cached VCEK certificate immediately
                info!("Using cached VCEK certificate (cache_key={})", cache_key);
                return Ok(cached.clone());
            }
        }

        // Build VCEK URL based on processor model and reported TCB
        let chip_id_hex = if attestation_report.chip_id.iter().all(|&b| b == 0) {
            return Err(
                "Hardware ID is 0s on attestation report. Confirm that MASK_CHIP_ID is set to 0."
                    .into(),
            );
        } else {
            match processor_model {
                snp::model::Generation::Milan | snp::model::Generation::Genoa => {
                    // Milan and Genoa use full chip_id
                    crypto::hex::to_hex(&attestation_report.chip_id).to_uppercase()
                }
                snp::model::Generation::Turin => {
                    // Turin uses only first 8 bytes of chip_id
                    crypto::hex::to_hex(&attestation_report.chip_id[0..8]).to_uppercase()
                }
            }
        };

        let vcek_url = match processor_model {
            snp::model::Generation::Milan | snp::model::Generation::Genoa => {
                let tcb = attestation_report.reported_tcb.as_milan_genoa();
                format!(
                "https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                processor_model,
                chip_id_hex,
                tcb.boot_loader,
                tcb.tee,
                tcb.snp,
                tcb.microcode
            )
            }
            snp::model::Generation::Turin => {
                let tcb = attestation_report.reported_tcb.as_turin();
                format!(
                    "https://kdsintf.amd.com/vcek/v1/{}/{}?fmcSPL={:02}&blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                    processor_model,
                    chip_id_hex,
                    tcb.fmc,
                    tcb.boot_loader,
                    tcb.tee,
                    tcb.snp,
                    tcb.microcode
                )
            }
        };

        let vcek_bytes = fetch_url_bytes(&vcek_url).await?;

        let vcek = Crypto::from_der(&vcek_bytes)
            .map_err(|e| format!("Failed to parse VCEK certificate: {}", e))?;

        debug!(
            "Using {} vcek pem:\n{}",
            processor_model,
            Crypto::to_pem(&vcek)
                .map_err(|e| format!("Failed to encode VCEK certificate: {}", e))?
        );

        // Store into cache if requested
        if self.use_cache {
            self.vcek_cache.insert(cache_key.clone(), vcek.clone());
            info!("Cached VCEK certificate (cache_key={})", cache_key);
        }

        Ok(vcek)
    }
}

#[cfg(target_arch = "wasm32")]
async fn fetch_url_bytes(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Use globalThis.fetch so this works in both browser and Node (wasm-bindgen-test runner)
    let global = js_sys::global();
    let fetch = js_sys::Reflect::get(&global, &JsValue::from_str("fetch"))
        .map_err(|_| "globalThis.fetch is not available")?;
    let fetch_fn: js_sys::Function = fetch
        .dyn_into()
        .map_err(|_| "globalThis.fetch is not a function")?;

    let fetch_promise: Promise = fetch_fn
        .call1(&global, &JsValue::from_str(url))
        .map_err(|e| format!("JS fetch invocation error: {:?}", e))?
        .dyn_into()
        .map_err(|_| "fetch() did not return a Promise")?;

    let resp = JsFuture::from(fetch_promise)
        .await
        .map_err(|e| format!("JS fetch error: {:?}", e))?;

    // If response.ok is false, surface status for easier debugging
    if let Ok(ok) = js_sys::Reflect::get(&resp, &JsValue::from_str("ok")) {
        if ok.as_bool() == Some(false) {
            let status = js_sys::Reflect::get(&resp, &JsValue::from_str("status"))
                .ok()
                .and_then(|v| v.as_f64())
                .map(|v| v as u16);
            return Err(format!("HTTP request failed (status={:?})", status).into());
        }
    }

    let array_buffer = js_sys::Reflect::get(&resp, &JsValue::from_str("arrayBuffer"))
        .map_err(|_| "fetch Response.arrayBuffer is not available")?;
    let array_buffer_fn: js_sys::Function = array_buffer
        .dyn_into()
        .map_err(|_| "Response.arrayBuffer is not a function")?;

    let ab_promise: Promise = array_buffer_fn
        .call0(&resp)
        .map_err(|e| format!("Response.arrayBuffer() threw: {:?}", e))?
        .dyn_into()
        .map_err(|_| "Response.arrayBuffer() did not return a Promise")?;
    let ab = JsFuture::from(ab_promise)
        .await
        .map_err(|e| format!("arrayBuffer await failed: {:?}", e))?;

    let u8arr = Uint8Array::new(&ab);
    let mut vec = vec![0u8; u8arr.length() as usize];
    u8arr.copy_to(&mut vec[..]);
    Ok(vec)
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_url_bytes(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use curl::easy::Easy;

    let mut response_data = Vec::new();
    let mut handle = Easy::new();
    handle.url(url)?;
    handle.follow_location(true)?;

    {
        let mut transfer = handle.transfer();
        transfer.write_function(|data| {
            response_data.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.perform()?;
    }

    let response_code = handle.response_code()?;
    if response_code != 200 {
        return Err(format!("HTTP request failed with status: {}", response_code).into());
    }

    Ok(response_data)
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use super::*;
    use crate::snp::model::Generation;

    // Two distinct real certificates, used only to tell cache entries apart.
    const MILAN_ARK: &[u8] = include_bytes!("pinned_arks/milan_ark.pem");
    const GENOA_ARK: &[u8] = include_bytes!("pinned_arks/genoa_ark.pem");

    fn cert(pem: &[u8]) -> Certificate {
        Crypto::from_pem(pem).expect("valid test certificate")
    }

    fn pem(c: &Certificate) -> String {
        Crypto::to_pem(c).expect("certificate encodes to PEM")
    }

    /// Regression test for #22: the ARK/ASK chain cache must return the entry
    /// matching the requested processor generation, not simply the first cached
    /// chain. Both lookups are cache hits, so no network access occurs.
    #[tokio::test]
    async fn chain_cache_is_keyed_by_generation() {
        let milan = cert(MILAN_ARK);
        let genoa = cert(GENOA_ARK);
        assert_ne!(pem(&milan), pem(&genoa), "test fixtures must differ");

        let mut fetcher = KdsFetcher::with_cache();
        fetcher
            .chain_cache
            .push((Generation::Milan, (milan.clone(), milan.clone())));
        fetcher
            .chain_cache
            .push((Generation::Genoa, (genoa.clone(), genoa.clone())));

        let (milan_ark, _) = fetcher
            .fetch_amd_chain(Generation::Milan)
            .await
            .expect("cached Milan chain");
        let (genoa_ark, _) = fetcher
            .fetch_amd_chain(Generation::Genoa)
            .await
            .expect("cached Genoa chain");

        assert_eq!(
            pem(&milan_ark),
            pem(&milan),
            "Milan lookup returned wrong chain"
        );
        assert_eq!(
            pem(&genoa_ark),
            pem(&genoa),
            "Genoa lookup returned wrong chain"
        );
    }
}
