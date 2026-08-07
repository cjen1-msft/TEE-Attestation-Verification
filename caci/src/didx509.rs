// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(async_crypto)]
use crypto::AsyncCryptoBackend;
#[cfg(sync_crypto)]
use crypto::CryptoBackend;

use crate::AciError;
use crypto::{base64::base64_encode_no_padding, CertificateBackend};
use x509_cert::{
    der::{asn1::ObjectIdentifier, Decode},
    ext::pkix::ExtendedKeyUsage,
};

const EXTENDED_KEY_USAGE_OID: &str = "2.5.29.37";

#[cfg(sync_crypto)]
pub(crate) fn verify_didx509(
    trusted_didx509: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
    leaf: &crypto::Certificate,
) -> Result<(), AciError> {
    let trusted = parse_didx509_prefix(trusted_didx509)?;
    let issuer = parse_didx509_prefix(issuer)?;
    if issuer.prefix != trusted.prefix {
        return Err(AciError::DidX509(format!(
            "issuer DID prefix {} does not match trusted DID prefix {}",
            issuer.prefix, trusted.prefix
        )));
    }

    let root = x5chain
        .last()
        .ok_or_else(|| AciError::Certificate("x5chain is empty".to_string()))?;
    let actual_fingerprint = sha256_base64(root)?;
    verify_didx509_fingerprint(&trusted, &actual_fingerprint)?;
    verify_didx509_eku(&trusted, leaf)
}

#[cfg(async_crypto)]
pub(crate) async fn verify_didx509_async(
    trusted_didx509: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
    leaf: &crypto::Certificate,
) -> Result<(), AciError> {
    let trusted = parse_didx509_prefix(trusted_didx509)?;
    let issuer = parse_didx509_prefix(issuer)?;
    if issuer.prefix != trusted.prefix {
        return Err(AciError::DidX509(format!(
            "issuer DID prefix {} does not match trusted DID prefix {}",
            issuer.prefix, trusted.prefix
        )));
    }

    let root = x5chain
        .last()
        .ok_or_else(|| AciError::Certificate("x5chain is empty".to_string()))?;
    let actual_fingerprint = sha256_base64_async(root).await?;
    verify_didx509_fingerprint(&trusted, &actual_fingerprint)?;
    verify_didx509_eku(&trusted, leaf)
}

fn verify_didx509_fingerprint(
    trusted: &ParsedDidX509Prefix<'_>,
    actual_fingerprint: &str,
) -> Result<(), AciError> {
    if actual_fingerprint != trusted.fingerprint {
        return Err(AciError::DidX509(format!(
            "x5chain root certificate fingerprint does not match trusted DID {}",
            trusted.raw
        )));
    }

    Ok(())
}

fn verify_didx509_eku(
    trusted: &ParsedDidX509Prefix<'_>,
    leaf: &crypto::Certificate,
) -> Result<(), AciError> {
    let required_oids = parse_didx509_eku_policies(trusted.raw)?;
    if required_oids.is_empty() {
        return Ok(());
    }

    let extension = crypto::Crypto::get_extension_value_by_oid(leaf, EXTENDED_KEY_USAGE_OID)
        .map_err(|e| AciError::DidX509(format!("failed to read leaf certificate EKU: {e}")))?;
    let extended_key_usage = extension
        .as_deref()
        .map(ExtendedKeyUsage::from_der)
        .transpose()
        .map_err(|e| AciError::DidX509(format!("failed to parse leaf certificate EKU: {e}")))?;

    for required_oid in required_oids {
        if !extended_key_usage
            .as_ref()
            .is_some_and(|eku| eku.0.contains(&required_oid))
        {
            return Err(AciError::DidX509(format!(
                "leaf certificate extended key usage does not contain required OID {required_oid}"
            )));
        }
    }

    Ok(())
}

fn parse_didx509_eku_policies(did: &str) -> Result<Vec<ObjectIdentifier>, AciError> {
    let mut required_oids = Vec::new();
    for policy in did.split("::").skip(1) {
        let Some(values) = policy.strip_prefix("eku:") else {
            return Err(AciError::DidX509(format!(
                "unsupported did:x509 policy {policy}"
            )));
        };
        for value in values.split(':') {
            required_oids.push(
                ObjectIdentifier::new(value).map_err(|e| {
                    AciError::DidX509(format!("invalid EKU policy OID {value}: {e}"))
                })?,
            );
        }
    }
    Ok(required_oids)
}

pub(crate) struct ParsedDidX509Prefix<'a> {
    pub(crate) prefix: &'a str,
    pub(crate) fingerprint: &'a str,
    pub(crate) raw: &'a str,
}

pub(crate) fn parse_didx509_prefix(did: &str) -> Result<ParsedDidX509Prefix<'_>, AciError> {
    let prefix = did.split_once("::").map_or(did, |(prefix, _)| prefix);
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

    Ok(ParsedDidX509Prefix {
        prefix,
        fingerprint,
        raw: did,
    })
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
