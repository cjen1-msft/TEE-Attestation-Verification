// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::time::Duration;
#[cfg(async_crypto)]
use std::{future::Future, pin::Pin};

use pkcs1::{RsaPssParams, TrailerField};
use x509_cert::der::{
    asn1::AnyRef, oid::ObjectIdentifier, pem::LineEnding, referenced::OwnedToRef, Decode,
    DecodePem, Encode, EncodePem,
};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::{Result, RsaPssSignatureKeyAlgorithm, SignatureKeyAlgorithm};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    inner: x509_cert::Certificate,
}

impl Certificate {
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: x509_cert::Certificate::from_pem(pem)?,
        })
    }

    pub fn from_pem_chain(pem: &[u8]) -> Result<Vec<Self>> {
        x509_cert::Certificate::load_pem_chain(pem)?
            .into_iter()
            .map(|inner| Ok(Self { inner }))
            .collect()
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: x509_cert::Certificate::from_der(der)?,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.inner.to_der()?)
    }

    pub fn to_pem(&self) -> Result<String> {
        Ok(self.inner.to_pem(LineEnding::LF)?)
    }

    pub fn public_key_spki_der(&self) -> Result<Vec<u8>> {
        Ok(self
            .inner
            .tbs_certificate
            .subject_public_key_info
            .to_der()?)
    }

    pub fn get_extension_value_by_oid(&self, oid: &str) -> Result<Option<Vec<u8>>> {
        let oid = ObjectIdentifier::new(oid)?;

        let extensions = match self.inner.tbs_certificate.extensions.as_ref() {
            Some(extensions) => extensions,
            None => return Ok(None),
        };

        Ok(extensions
            .iter()
            .find(|extension| extension.extn_id == oid)
            .map(|extension| extension.extn_value.as_bytes().to_vec()))
    }

    pub fn tbs_certificate_der(&self) -> Result<Vec<u8>> {
        Ok(self.inner.tbs_certificate.to_der()?)
    }

    pub fn signature_bytes(&self) -> &[u8] {
        self.inner.signature.raw_bytes()
    }

    pub fn signature_algorithm(&self) -> Result<SignatureKeyAlgorithm> {
        parse_signature_algorithm(&self.inner.signature_algorithm)
    }

    pub fn subject_matches_issuer_of(&self, subject: &Self) -> bool {
        // This constrained validator intentionally uses strict structural Name
        // equality rather than the full RFC 5280 Section 7.1 comparison rules.
        // AMD and UVM collateral use structurally matching issuer/subject names.
        self.inner.tbs_certificate.subject == subject.inner.tbs_certificate.issuer
    }

    pub fn is_self_issued(&self) -> bool {
        self.inner.tbs_certificate.subject == self.inner.tbs_certificate.issuer
    }

    pub fn is_valid_at(&self, unix_time: Duration) -> bool {
        let validity = &self.inner.tbs_certificate.validity;

        validity.not_before.to_unix_duration() <= unix_time
            && unix_time <= validity.not_after.to_unix_duration()
    }

    pub fn has_ca_basic_constraints(&self) -> Result<bool> {
        Ok(self
            .basic_constraints()?
            .map(|constraints| constraints.ca)
            .unwrap_or(false))
    }

    pub fn can_issue_certificates(&self) -> Result<bool> {
        let Some(basic_constraints) = self.basic_constraints()? else {
            return Ok(false);
        };

        if !basic_constraints.ca {
            return Ok(false);
        }

        Ok(self
            .key_usage()?
            .map(|key_usage| key_usage.key_cert_sign())
            .unwrap_or(true))
    }

    pub fn path_len_constraint(&self) -> Result<Option<u8>> {
        Ok(self
            .basic_constraints()?
            .and_then(|constraints| constraints.path_len_constraint))
    }

    pub fn validate_issuer_for_subject(
        &self,
        subject: &Self,
        unix_time: Duration,
        ca_certificates_below: usize,
    ) -> Result<()> {
        self.validate_supported_critical_extensions()?;
        subject.validate_supported_critical_extensions()?;

        if !self.subject_matches_issuer_of(subject) {
            return Err("Certificate issuer name does not match issuer subject name".into());
        }

        if !self.is_valid_at(unix_time) {
            return Err("Issuer certificate is not valid at verification time".into());
        }

        if !subject.is_valid_at(unix_time) {
            return Err("Subject certificate is not valid at verification time".into());
        }

        if !self.can_issue_certificates()? {
            return Err("Issuer certificate is not a CA allowed to sign certificates".into());
        }

        if let Some(path_len_constraint) = self.path_len_constraint()? {
            if ca_certificates_below > usize::from(path_len_constraint) {
                return Err(format!(
                    "Issuer path length constraint exceeded: allowed {}, got {}",
                    path_len_constraint, ca_certificates_below
                )
                .into());
            }
        }

        Ok(())
    }

    pub fn validate_trust_anchor_for_subject(
        &self,
        subject: &Self,
        unix_time: Duration,
    ) -> Result<()> {
        subject.validate_supported_critical_extensions()?;

        if !self.subject_matches_issuer_of(subject) {
            return Err("Certificate issuer name does not match trust anchor subject name".into());
        }

        if !subject.is_valid_at(unix_time) {
            return Err("Subject certificate is not valid at verification time".into());
        }

        Ok(())
    }

    #[cfg(sync_crypto)]
    pub fn verify_ordered_chain<'a>(
        trusted_certs: &[&'a Self],
        untrusted_chain: &[&'a Self],
        leaf: &'a Self,
        unix_time: Duration,
        mut verify_signature: impl FnMut(&Self, &Self) -> Result<()>,
    ) -> Result<()> {
        let ordered_chain = Self::ordered_chain(untrusted_chain, leaf);
        Self::validate_ordered_path(&ordered_chain, unix_time)?;

        Self::for_each_validated_path_edge(
            trusted_certs,
            &ordered_chain,
            unix_time,
            |issuer, subject| verify_signature(issuer, subject),
        )
    }

    #[cfg(async_crypto)]
    pub async fn verify_ordered_chain_async<'a, F>(
        trusted_certs: &[&'a Self],
        untrusted_chain: &[&'a Self],
        leaf: &'a Self,
        unix_time: Duration,
        mut verify_signature: F,
    ) -> Result<()>
    where
        F: for<'b> FnMut(&'b Self, &'b Self) -> Pin<Box<dyn Future<Output = Result<()>> + 'b>>,
    {
        let ordered_chain = Self::ordered_chain(untrusted_chain, leaf);
        Self::validate_ordered_path(&ordered_chain, unix_time)?;

        let mut prev: Option<&Self> = None;

        for (index, &cert) in ordered_chain.iter().enumerate() {
            let ca_certificates_below = Self::ca_certificates_before_leaf(&ordered_chain, index)?;

            if let Some(issuer) = prev {
                issuer.validate_issuer_for_subject(cert, unix_time, ca_certificates_below)?;
                verify_signature(issuer, cert).await?;
            } else {
                let mut verified = false;
                for &trusted in trusted_certs {
                    if trusted
                        .validate_trust_anchor_for_subject(cert, unix_time)
                        .is_ok()
                        && verify_signature(trusted, cert).await.is_ok()
                    {
                        verified = true;
                        break;
                    }
                }

                if !verified {
                    return Err("Failed to verify certificate: no matching trusted issuer".into());
                }
            }

            prev = Some(cert);
        }

        Ok(())
    }

    fn ordered_chain<'a>(untrusted_chain: &[&'a Self], leaf: &'a Self) -> Vec<&'a Self> {
        untrusted_chain
            .iter()
            .copied()
            .chain(std::iter::once(leaf))
            .collect()
    }

    #[cfg(sync_crypto)]
    fn for_each_validated_path_edge(
        trusted_certs: &[&Self],
        ordered_chain: &[&Self],
        unix_time: Duration,
        mut verify_signature: impl FnMut(&Self, &Self) -> Result<()>,
    ) -> Result<()> {
        let mut prev: Option<&Self> = None;

        for (index, &cert) in ordered_chain.iter().enumerate() {
            let ca_certificates_below = Self::ca_certificates_before_leaf(ordered_chain, index)?;

            if let Some(issuer) = prev {
                issuer.validate_issuer_for_subject(cert, unix_time, ca_certificates_below)?;
                verify_signature(issuer, cert)?;
            } else {
                trusted_certs
                    .iter()
                    .find(|trusted| {
                        trusted
                            .validate_trust_anchor_for_subject(cert, unix_time)
                            .and_then(|_| verify_signature(trusted, cert))
                            .is_ok()
                    })
                    .ok_or("Failed to verify certificate: no matching trusted issuer")?;
            }

            prev = Some(cert);
        }

        Ok(())
    }

    fn validate_ordered_path(chain: &[&Self], unix_time: Duration) -> Result<()> {
        Self::reject_duplicate_der_certificates(chain)?;

        for cert in chain {
            cert.validate_supported_critical_extensions()?;
            if !cert.is_valid_at(unix_time) {
                return Err("Certificate is not valid at verification time".into());
            }
        }

        Ok(())
    }

    fn ca_certificates_before_leaf(chain: &[&Self], start_index: usize) -> Result<usize> {
        if chain.is_empty() || start_index >= chain.len() {
            return Ok(0);
        }

        chain[start_index..chain.len() - 1]
            .iter()
            .try_fold(0usize, |count, cert| {
                Ok(count + usize::from(cert.has_ca_basic_constraints()? && !cert.is_self_issued()))
            })
    }

    fn validate_supported_critical_extensions(&self) -> Result<()> {
        let Some(extensions) = self.inner.tbs_certificate.extensions.as_ref() else {
            return Ok(());
        };

        for extension in extensions {
            if extension.critical && !is_supported_critical_extension(&extension.extn_id) {
                return Err(unsupported_critical_extension_error(&extension.extn_id).into());
            }
        }

        Ok(())
    }

    fn reject_duplicate_der_certificates(chain: &[&Self]) -> Result<()> {
        let mut seen = Vec::with_capacity(chain.len());

        for cert in chain {
            let der = cert.to_der()?;
            if seen.iter().any(|seen_der| seen_der == &der) {
                return Err("Certificate chain contains a duplicate certificate".into());
            }
            seen.push(der);
        }

        Ok(())
    }

    fn basic_constraints(&self) -> Result<Option<BasicConstraints>> {
        Ok(self
            .inner
            .tbs_certificate
            .get::<BasicConstraints>()?
            .map(|(_, constraints)| constraints))
    }

    fn key_usage(&self) -> Result<Option<KeyUsage>> {
        Ok(self
            .inner
            .tbs_certificate
            .get::<KeyUsage>()?
            .map(|(_, key_usage)| key_usage))
    }
}

fn parse_signature_algorithm(
    algorithm: &AlgorithmIdentifierOwned,
) -> Result<SignatureKeyAlgorithm> {
    let algorithm_ref = algorithm.owned_to_ref();

    if algorithm_ref.oid == oid::RSA_PSS {
        let parameters = algorithm_ref
            .parameters
            .ok_or("RSA-PSS signature algorithm parameters are required")?;

        return parse_rsa_pss_signature_algorithm(parameters);
    }

    Err(format!("Unsupported signature algorithm OID: {}", algorithm_ref.oid).into())
}

fn parse_rsa_pss_signature_algorithm(parameters: AnyRef<'_>) -> Result<SignatureKeyAlgorithm> {
    let parameters = parameters.decode_as::<RsaPssParams<'_>>()?;
    let expected_algorithm = RsaPssSignatureKeyAlgorithm::Ps384;

    if parameters.hash.oid != oid::SHA384
        || !parameters
            .hash
            .parameters
            .map(|parameters| parameters.is_null())
            .unwrap_or(true)
    {
        return Err("Unsupported RSA-PSS hash algorithm parameters".into());
    }

    let Some(mask_gen_hash) = parameters.mask_gen.parameters else {
        return Err("RSA-PSS MGF1 parameters are required".into());
    };

    if parameters.mask_gen.oid != oid::MGF1
        || mask_gen_hash.oid != oid::SHA384
        || !mask_gen_hash
            .parameters
            .map(|parameters| parameters.is_null())
            .unwrap_or(true)
    {
        return Err("Unsupported RSA-PSS mask generation parameters".into());
    }

    if usize::from(parameters.salt_len) != expected_algorithm.salt_len() {
        return Err(format!(
            "Unsupported RSA-PSS salt length: expected {}, got {}",
            expected_algorithm.salt_len(),
            parameters.salt_len
        )
        .into());
    }

    if parameters.trailer_field != TrailerField::BC {
        return Err("Unsupported RSA-PSS trailer field".into());
    }

    Ok(SignatureKeyAlgorithm::RsaPss(expected_algorithm))
}

fn is_supported_critical_extension(oid: &ObjectIdentifier) -> bool {
    *oid == oid::BASIC_CONSTRAINTS || *oid == oid::KEY_USAGE
}

fn unsupported_critical_extension_error(oid: &ObjectIdentifier) -> String {
    if *oid == oid::NAME_CONSTRAINTS {
        return "Critical nameConstraints extension is unsupported; non-critical nameConstraints are ignored by this constrained offline validator".to_string();
    }

    if is_policy_extension(oid) {
        return format!(
            "Critical policy extension {oid} is unsupported; non-critical policy extensions are ignored by this constrained offline validator"
        );
    }

    format!("Unsupported critical certificate extension: {oid}")
}

fn is_policy_extension(oid: &ObjectIdentifier) -> bool {
    *oid == oid::CERTIFICATE_POLICIES
        || *oid == oid::POLICY_MAPPINGS
        || *oid == oid::POLICY_CONSTRAINTS
        || *oid == oid::INHIBIT_ANY_POLICY
}

mod oid {
    use x509_cert::der::oid::ObjectIdentifier;

    pub const RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
    pub const MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
    pub const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
    pub const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
    pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
    pub const NAME_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.30");
    pub const CERTIFICATE_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");
    pub const POLICY_MAPPINGS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.33");
    pub const POLICY_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.36");
    pub const INHIBIT_ANY_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.54");
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use x509_cert::der::Encode;

    use super::Certificate;
    use crate::{RsaPssSignatureKeyAlgorithm, SignatureKeyAlgorithm};

    const MILAN_ARK: &[u8] = include_bytes!("test_data/milan_ark.pem");
    const MILAN_ASK: &[u8] = include_bytes!("test_data/milan_ask.pem");
    const MILAN_VCEK: &[u8] = include_bytes!("test_data/milan_vcek.pem");

    fn cert(pem: &[u8]) -> Certificate {
        Certificate::from_pem(pem).unwrap()
    }

    #[test]
    fn from_der_round_trips_from_pem_certificate() {
        let cert = cert(MILAN_VCEK);
        let der = cert.to_der().expect("DER encoding should succeed");
        let reparsed = Certificate::from_der(&der).expect("DER should parse");

        assert_eq!(reparsed.to_der().expect("Reparsed DER should encode"), der);
    }

    #[test]
    fn get_public_key_returns_subject_public_key_info_der() {
        let cert = cert(MILAN_ARK);

        assert_eq!(
            cert.public_key_spki_der()
                .expect("SPKI extraction should succeed"),
            cert.inner
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .expect("SPKI DER should encode")
        );
    }

    #[test]
    fn extension_lookup_returns_expected_bootloader_value() {
        let vcek = cert(MILAN_VCEK);

        let bootloader = vcek
            .get_extension_value_by_oid("1.3.6.1.4.1.3704.1.3.1")
            .expect("BootLoader OID lookup should succeed")
            .expect("BootLoader OID should be present in Milan VCEK");

        assert_eq!(bootloader, vec![0x02, 0x01, 0x04]);
    }

    #[test]
    fn extension_lookup_returns_expected_hwid_value() {
        let vcek = cert(MILAN_VCEK);

        let hwid = vcek
            .get_extension_value_by_oid("1.3.6.1.4.1.3704.1.4")
            .expect("HWID OID lookup should succeed")
            .expect("HWID OID should be present in Milan VCEK");

        assert_eq!(
            hwid,
            [
                79, 251, 92, 180, 253, 89, 79, 63, 238, 101, 40, 252, 63, 177, 3, 112, 187, 56,
                171, 232, 157, 205, 91, 162, 207, 10, 182, 161, 29, 242, 202, 40, 42, 221, 81, 107,
                239, 69, 168, 144, 168, 201, 249, 115, 43, 220, 166, 143, 159, 63, 22, 196, 46,
                132, 96, 48, 168, 0, 41, 93, 190, 177, 155, 165,
            ]
        );
    }

    #[test]
    fn extension_lookup_returns_none_for_missing_oid() {
        let vcek = cert(MILAN_VCEK);

        let missing = vcek
            .get_extension_value_by_oid("1.2.3.4.5.6.7.8.9")
            .expect("Missing OID lookup should not fail");

        assert!(missing.is_none());
    }

    #[test]
    fn extension_lookup_rejects_malformed_oid() {
        let vcek = cert(MILAN_VCEK);

        vcek.get_extension_value_by_oid("not-an-oid")
            .expect_err("Malformed OID should fail");
    }

    #[test]
    fn pem_chain_parsing_preserves_input_order() {
        let mut pem_chain = Vec::new();
        pem_chain.extend_from_slice(MILAN_ASK);
        pem_chain.push(b'\n');
        pem_chain.extend_from_slice(MILAN_ARK);

        let chain = Certificate::from_pem_chain(&pem_chain).expect("PEM chain should parse");

        assert_eq!(chain.len(), 2);
        assert_eq!(
            chain[0].to_der().expect("ASK DER should encode"),
            cert(MILAN_ASK)
                .to_der()
                .expect("ASK fixture DER should encode")
        );
        assert_eq!(
            chain[1].to_der().expect("ARK DER should encode"),
            cert(MILAN_ARK)
                .to_der()
                .expect("ARK fixture DER should encode")
        );
    }

    #[test]
    fn pem_encoding_round_trips_through_from_pem() {
        let cert = cert(MILAN_VCEK);
        let pem = cert.to_pem().expect("PEM encoding should succeed");
        let reparsed = Certificate::from_pem(pem.as_bytes()).expect("PEM should parse");

        assert_eq!(
            reparsed.to_der().expect("Reparsed DER should encode"),
            cert.to_der().expect("Original DER should encode")
        );
    }

    #[test]
    fn signature_algorithm_reports_rsa_pss() {
        let cert = cert(MILAN_VCEK);

        assert_eq!(
            cert.signature_algorithm()
                .expect("Signature algorithm should parse"),
            SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384)
        );
    }

    #[test]
    fn rsa_pss_signature_algorithm_requires_parameters() {
        let algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: super::oid::RSA_PSS,
            parameters: None,
        };

        super::parse_signature_algorithm(&algorithm)
            .expect_err("RSA-PSS parameters default to SHA-1 and should be rejected");
    }

    #[test]
    fn certificate_path_metadata_matches_amd_chain() {
        let ark = cert(MILAN_ARK);
        let ask = cert(MILAN_ASK);
        let vcek = cert(MILAN_VCEK);

        assert!(ark.subject_matches_issuer_of(&ask));
        assert!(ask.subject_matches_issuer_of(&vcek));
        assert!(!ark.subject_matches_issuer_of(&vcek));
        assert!(ark.is_self_issued());
        assert!(!ask.is_self_issued());

        assert!(ark
            .can_issue_certificates()
            .expect("ARK constraints should parse"));
        assert!(ask
            .can_issue_certificates()
            .expect("ASK constraints should parse"));
        assert!(!vcek
            .can_issue_certificates()
            .expect("VCEK constraints should parse"));
        assert_eq!(
            ask.path_len_constraint()
                .expect("ASK path length should parse"),
            Some(0)
        );

        let chain = [&ask, &vcek];
        assert_eq!(
            Certificate::ca_certificates_before_leaf(&chain, 0).expect("CA count should parse"),
            1
        );
        assert_eq!(
            Certificate::ca_certificates_before_leaf(&chain, 1).expect("CA count should parse"),
            0
        );

        let chain_with_self_issued_ca = [&ark, &ask, &vcek];
        assert_eq!(
            Certificate::ca_certificates_before_leaf(&chain_with_self_issued_ca, 0)
                .expect("CA count should parse"),
            1
        );
    }

    #[test]
    fn issuer_validation_checks_names_validity_and_constraints() {
        let ark = cert(MILAN_ARK);
        let ask = cert(MILAN_ASK);
        let vcek = cert(MILAN_VCEK);
        let valid_time = Duration::from_secs(1_770_000_000);

        ark.validate_issuer_for_subject(&ask, valid_time, 0)
            .expect("ARK should be able to issue ASK");
        ask.validate_issuer_for_subject(&vcek, valid_time, 0)
            .expect("ASK should be able to issue VCEK");

        ark.validate_issuer_for_subject(&vcek, valid_time, 0)
            .expect_err("ARK subject name should not match VCEK issuer name");
        ask.validate_issuer_for_subject(&vcek, Duration::from_secs(1), 0)
            .expect_err("Expired or not-yet-valid certificates should fail");
        ask.validate_issuer_for_subject(&vcek, valid_time, 1)
            .expect_err("ASK pathLen=0 should reject subordinate CA certificates");
    }

    #[test]
    fn ordered_path_rejects_duplicate_certificates() {
        let ask = cert(MILAN_ASK);
        let vcek = cert(MILAN_VCEK);
        let valid_time = Duration::from_secs(1_770_000_000);

        Certificate::validate_ordered_path(&[&ask, &vcek], valid_time)
            .expect("Unique ordered path should validate");
        Certificate::validate_ordered_path(&[&ask, &vcek, &ask], valid_time)
            .expect_err("Duplicate DER certificate should fail");
    }

    #[test]
    fn critical_extension_policy_allows_only_processed_extensions() {
        let mut vcek = cert(MILAN_VCEK);
        let extensions = vcek
            .inner
            .tbs_certificate
            .extensions
            .as_mut()
            .expect("VCEK should have extensions");
        let extension = extensions
            .iter_mut()
            .find(|extension| {
                extension.extn_id != super::oid::BASIC_CONSTRAINTS
                    && extension.extn_id != super::oid::KEY_USAGE
            })
            .expect("VCEK should have at least one unsupported extension");

        extension.critical = true;

        vcek.validate_supported_critical_extensions()
            .expect_err("Unsupported critical extension should fail");
    }

    #[test]
    fn critical_name_constraints_and_policy_extensions_are_documented_as_unsupported() {
        let name_constraints_error =
            super::unsupported_critical_extension_error(&super::oid::NAME_CONSTRAINTS);
        let policy_error =
            super::unsupported_critical_extension_error(&super::oid::CERTIFICATE_POLICIES);

        assert!(name_constraints_error.contains("non-critical nameConstraints are ignored"));
        assert!(policy_error.contains("non-critical policy extensions are ignored"));
    }
}
