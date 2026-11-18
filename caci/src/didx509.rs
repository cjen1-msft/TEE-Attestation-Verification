// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(async_crypto)]
use crypto::AsyncCryptoBackend;
#[cfg(sync_crypto)]
use crypto::CryptoBackend;

use crate::AciError;
use crypto::base64::base64_encode_no_padding;

#[cfg(sync_crypto)]
pub(crate) fn verify_didx509(
    trusted_didx509: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
    leaf: &crypto::Certificate,
) -> Result<(), AciError> {
    let root = x5chain
        .last()
        .ok_or_else(|| AciError::Certificate("x5chain is empty".to_string()))?;
    let actual_fingerprint = sha256_base64(root)?;
    verify_policy(trusted_didx509, issuer, &actual_fingerprint, leaf)
}

#[cfg(async_crypto)]
pub(crate) async fn verify_didx509_async(
    trusted_didx509: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
    leaf: &crypto::Certificate,
) -> Result<(), AciError> {
    let root = x5chain
        .last()
        .ok_or_else(|| AciError::Certificate("x5chain is empty".to_string()))?;
    let actual_fingerprint = sha256_base64_async(root).await?;
    verify_policy(trusted_didx509, issuer, &actual_fingerprint, leaf)
}

fn verify_policy(
    trusted_didx509: &str,
    issuer: &str,
    actual_fingerprint: &str,
    leaf: &crypto::Certificate,
) -> Result<(), AciError> {
    let (trusted_prefix, policy) = match trusted_didx509.split_once("::") {
        Some((prefix, policy)) => (prefix, Some(policy)),
        None => (trusted_didx509, None),
    };
    let fingerprint = parse_fingerprint(trusted_prefix)?;
    // The signed issuer identifies the root. Only the caller supplies the trusted policy.
    let issuer_prefix = issuer.split_once("::").map_or(issuer, |(prefix, _)| prefix);
    if issuer_prefix != trusted_prefix {
        return Err(AciError::DidX509(format!(
            "issuer DID prefix {issuer_prefix} does not match trusted DID prefix {trusted_prefix}"
        )));
    }
    if actual_fingerprint != fingerprint {
        return Err(AciError::DidX509(format!(
            "x5chain root certificate fingerprint does not match trusted DID {trusted_didx509}"
        )));
    }
    if let Some(policy) = policy {
        let oid = policy.strip_prefix("eku:").ok_or_else(|| {
            AciError::DidX509("expected trusted DID policy ::eku:<OID>".to_string())
        })?;
        crypto::require_extended_key_usage(leaf, oid)
            .map_err(|e| AciError::DidX509(e.to_string()))?;
    }
    Ok(())
}

fn parse_fingerprint(prefix: &str) -> Result<&str, AciError> {
    let mut tokens = prefix.split(':');
    let scheme = tokens.next();
    let method = tokens.next();
    let version = tokens.next();
    let hash = tokens.next();
    let fingerprint = tokens.next();
    if tokens.next().is_some()
        || scheme != Some("did")
        || method != Some("x509")
        || version != Some("0")
        || hash != Some("sha256")
    {
        return Err(AciError::DidX509(
            "expected did:x509:0:sha256:<fingerprint>".to_string(),
        ));
    }

    let fingerprint =
        fingerprint.ok_or_else(|| AciError::DidX509("missing fingerprint".to_string()))?;
    if fingerprint.is_empty() {
        return Err(AciError::DidX509("empty fingerprint".to_string()));
    }

    Ok(fingerprint)
}

#[cfg(sync_crypto)]
pub(crate) fn sha256_base64(bytes: &[u8]) -> Result<String, AciError> {
    let digest = <crypto::Crypto as CryptoBackend>::digest(crypto::DigestAlgorithm::Sha256, bytes)
        .map_err(|e| {
            AciError::DidX509(format!(
                "failed to compute DID x509 SHA-256 fingerprint: {e}"
            ))
        })?;
    Ok(base64_encode_no_padding(&digest))
}

#[cfg(async_crypto)]
async fn sha256_base64_async(bytes: &[u8]) -> Result<String, AciError> {
    let digest =
        <crypto::Crypto as AsyncCryptoBackend>::digest(crypto::DigestAlgorithm::Sha256, bytes)
            .await
            .map_err(|e| {
                AciError::DidX509(format!(
                    "failed to compute DID x509 SHA-256 fingerprint: {e}"
                ))
            })?;
    Ok(base64_encode_no_padding(&digest))
}
