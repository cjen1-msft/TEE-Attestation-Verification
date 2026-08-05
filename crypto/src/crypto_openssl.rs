// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native OpenSSL-backed cryptographic backend.
//!
//! This backend uses OpenSSL for X.509 certificate parsing and encoding,
//! certificate-chain verification, and SEV-SNP attestation report signature
//! verification. It is the native backend selected when `crypto_openssl` is
//! enabled for a non-`wasm32` target.

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::asn1::{Asn1Object, Asn1ObjectRef, Asn1Time};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier as OpenSslVerifier};
use openssl::stack::Stack;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{GeneralName as OpenSslGeneralName, GeneralNameRef};
use openssl_sys::{
    ASN1_STRING_get0_data, ASN1_STRING_length, ASN1_STRING_type, NID_ext_key_usage,
    NID_subject_alt_name, OBJ_obj2txt, X509_EXTENSION_get_critical, X509_EXTENSION_get_data,
    X509_EXTENSION_get_object, X509_get_ext, X509_get_ext_by_OBJ, X509_get_ext_count,
    X509_get_ext_d2i, X509_get_extension_flags, X509_get_key_usage, X509v3_KU_KEY_CERT_SIGN,
    EXFLAG_CA, GENERAL_NAME, GEN_DIRNAME, GEN_DNS, GEN_EDIPARTY, GEN_EMAIL, GEN_IPADD,
    GEN_OTHERNAME, GEN_RID, GEN_URI, GEN_X400, V_ASN1_IA5STRING, V_ASN1_PRINTABLESTRING,
    V_ASN1_UTF8STRING, X509_NAME_ENTRY,
};
use std::cmp::Ordering;
use std::os::raw::c_int;

use super::{
    compatible_key_and_signature, AttributeTypeAndValue, CertificateBackend, CryptoBackend,
    DigestAlgorithm, DistinguishedName, EcSignatureKeyAlgorithm, GeneralName, KeyBackend, Result,
    RsaPkcs1v15SignatureKeyAlgorithm, RsaPssSignatureKeyAlgorithm, SignatureBackend,
    SignatureKeyAlgorithm,
};

extern "C" {
    fn X509_NAME_ENTRY_set(entry: *const X509_NAME_ENTRY) -> c_int;
    fn i2d_GENERAL_NAME(name: *const GENERAL_NAME, output: *mut *mut u8) -> c_int;
    fn i2d_GENERAL_NAMES(
        names: *const openssl_sys::stack_st_GENERAL_NAME,
        output: *mut *mut u8,
    ) -> c_int;
    fn i2d_EXTENDED_KEY_USAGE(
        usages: *const openssl_sys::stack_st_ASN1_OBJECT,
        output: *mut *mut u8,
    ) -> c_int;
    fn i2d_X509_NAME_ENTRY(entry: *const X509_NAME_ENTRY, output: *mut *mut u8) -> c_int;
}

pub struct Crypto;

type Certificate = openssl::x509::X509;

pub struct Key {
    key: PKey<Public>,
    verification: OpenSslKeyVerification,
}

pub enum Signature {
    Ecdsa {
        algorithm: EcSignatureKeyAlgorithm,
        der: Vec<u8>,
    },
    RsaPss {
        algorithm: RsaPssSignatureKeyAlgorithm,
        raw: Vec<u8>,
    },
    RsaPkcs1v15 {
        algorithm: RsaPkcs1v15SignatureKeyAlgorithm,
        raw: Vec<u8>,
    },
}

enum OpenSslKeyVerification {
    Ecdsa {
        algorithm: EcSignatureKeyAlgorithm,
    },
    RsaPss {
        algorithm: RsaPssSignatureKeyAlgorithm,
    },
    RsaPkcs1v15 {
        algorithm: RsaPkcs1v15SignatureKeyAlgorithm,
    },
}

impl KeyBackend for Key {
    fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let key = PKey::public_key_from_der(spki_der)?;
        let verification = OpenSslKeyVerification::from_key_algorithm(&key, algorithm)?;

        Ok(Key { key, verification })
    }
}

impl SignatureBackend for Signature {
    fn from_bytes(signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(algorithm) => {
                let der = EcdsaSig::from_der(signature)
                    .map_err(|e| format!("Failed to parse DER ECDSA signature: {:?}", e))?
                    .to_der()?;
                Ok(Self::Ecdsa { algorithm, der })
            }
            SignatureKeyAlgorithm::RsaPss(algorithm) => Ok(Self::RsaPss {
                algorithm,
                raw: signature.to_vec(),
            }),
            SignatureKeyAlgorithm::RsaPkcs1v15(algorithm) => Ok(Self::RsaPkcs1v15 {
                algorithm,
                raw: signature.to_vec(),
            }),
        }
    }

    fn from_ec_components(r: &[u8], s: &[u8], algorithm: EcSignatureKeyAlgorithm) -> Result<Self> {
        let r = ec_component_from_bytes("r", r, algorithm)?;
        let s = ec_component_from_bytes("s", s, algorithm)?;
        let der = EcdsaSig::from_private_components(r, s)?.to_der()?;

        Ok(Self::Ecdsa { algorithm, der })
    }
}

impl CertificateBackend for Crypto {
    type Certificate = Certificate;

    fn from_pem(pem: &[u8]) -> Result<Self::Certificate> {
        openssl::x509::X509::from_pem(pem).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn from_pem_chain(pem: &[u8]) -> Result<Vec<Self::Certificate>> {
        openssl::x509::X509::stack_from_pem(pem)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn from_der(der: &[u8]) -> Result<Self::Certificate> {
        openssl::x509::X509::from_der(der).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn to_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.to_der()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn to_pem(cert: &Self::Certificate) -> Result<String> {
        let pem = cert
            .to_pem()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        String::from_utf8(pem).map_err(|e| format!("Failed to decode PEM as UTF-8: {:?}", e).into())
    }

    fn get_public_key(cert: &Self::Certificate) -> Result<Vec<u8>> {
        let pub_key = cert.public_key()?;
        Ok(pub_key.public_key_to_der()?)
    }

    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>> {
        let oid = Asn1Object::from_str(oid)
            .map_err(|e| format!("Invalid extension OID {}: {:?}", oid, e))?;

        unsafe {
            let index = X509_get_ext_by_OBJ(cert.as_ptr(), oid.as_ptr(), -1);
            if index == -1 {
                return Ok(None);
            }

            let extension = X509_get_ext(cert.as_ptr(), index);
            if extension.is_null() {
                return Err("OpenSSL returned null extension pointer".into());
            }

            let data = X509_EXTENSION_get_data(extension);
            if data.is_null() {
                return Err("OpenSSL returned null extension data".into());
            }

            let len = ASN1_STRING_length(data.cast());
            if len < 0 {
                return Err("OpenSSL returned negative extension length".into());
            }

            let data_ptr = ASN1_STRING_get0_data(data.cast());
            if data_ptr.is_null() {
                return Err("OpenSSL returned null extension bytes".into());
            }

            let bytes = std::slice::from_raw_parts(data_ptr, len as usize).to_vec();
            Ok(Some(bytes))
        }
    }

    fn subject_name(cert: &Self::Certificate) -> String {
        format!("{:?}", cert.subject_name())
    }

    fn issuer_name(cert: &Self::Certificate) -> String {
        format!("{:?}", cert.issuer_name())
    }

    fn subject_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        Ok(cert.subject_name().to_der()?)
    }

    fn issuer_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        Ok(cert.issuer_name().to_der()?)
    }

    fn subject_distinguished_name(cert: &Self::Certificate) -> Result<DistinguishedName> {
        let expected_rdn_count = validate_subject_name_der(&cert.subject_name().to_der()?)?;
        let mut distinguished_name = Vec::<Vec<(Vec<u8>, AttributeTypeAndValue)>>::new();
        let mut current_set = None;

        for entry in cert.subject_name().entries() {
            let set = unsafe { X509_NAME_ENTRY_set(entry.as_ptr()) };
            if set < 0 {
                return Err("OpenSSL returned a negative RDN set index".into());
            }

            match current_set {
                Some(previous) if set == previous => {}
                Some(previous) if set == previous + 1 => {
                    distinguished_name.push(Vec::new());
                    current_set = Some(set);
                }
                None if set == 0 => {
                    distinguished_name.push(Vec::new());
                    current_set = Some(set);
                }
                _ => {
                    return Err("Certificate subject contains an empty or out-of-order RDN".into());
                }
            }

            distinguished_name
                .last_mut()
                .expect("an RDN was just inserted")
                .push((
                    name_entry_der(entry)?,
                    AttributeTypeAndValue {
                        oid: dotted_oid(entry.object())?,
                        value: directory_string(entry.data())?,
                    },
                ));
        }

        if distinguished_name.len() != expected_rdn_count {
            return Err("OpenSSL omitted an RDN from the certificate subject".into());
        }
        Ok(distinguished_name
            .into_iter()
            .map(|mut rdn| {
                rdn.sort_by(|left, right| left.0.cmp(&right.0));
                rdn.into_iter().map(|(_, attribute)| attribute).collect()
            })
            .collect())
    }

    fn subject_alt_names(cert: &Self::Certificate) -> Result<Vec<GeneralName>> {
        let Some(names) = (unsafe {
            decoded_extension_stack::<OpenSslGeneralName>(
                cert,
                NID_subject_alt_name,
                "subjectAltName",
            )
        })?
        else {
            return Ok(Vec::new());
        };
        if names.is_empty() {
            return Err("subjectAltName must contain at least one GeneralName".into());
        }
        ensure_canonical_extension(
            cert,
            oid::SUBJECT_ALT_NAME,
            encoded_stack_der(&names, i2d_GENERAL_NAMES, "subjectAltName")?,
            "subjectAltName",
        )?;
        names.iter().map(decode_general_name).collect()
    }

    fn extended_key_usage_oids(cert: &Self::Certificate) -> Result<Vec<String>> {
        let Some(usages) = (unsafe {
            decoded_extension_stack::<Asn1Object>(cert, NID_ext_key_usage, "extendedKeyUsage")
        })?
        else {
            return Ok(Vec::new());
        };
        if usages.is_empty() {
            return Err("extendedKeyUsage must contain at least one OID".into());
        }
        ensure_canonical_extension(
            cert,
            oid::EXTENDED_KEY_USAGE,
            encoded_stack_der(&usages, i2d_EXTENDED_KEY_USAGE, "extendedKeyUsage")?,
            "extendedKeyUsage",
        )?;
        usages.iter().map(dotted_oid).collect()
    }

    fn is_valid_at(cert: &Self::Certificate, unix_time: std::time::Duration) -> Result<bool> {
        let unix_time = unix_time
            .as_secs()
            .try_into()
            .map_err(|_| "Unix time does not fit OpenSSL time_t")?;
        let unix_time = Asn1Time::from_unix(unix_time)?;

        Ok(cert.not_before().compare(&unix_time)? != Ordering::Greater
            && cert.not_after().compare(&unix_time)? != Ordering::Less)
    }

    fn version(cert: &Self::Certificate) -> Result<u8> {
        cert.version()
            .try_into()
            .map_err(|_| "OpenSSL returned a negative certificate version".into())
    }

    fn basic_constraints(cert: &Self::Certificate) -> Result<Option<super::BasicConstraints>> {
        let critical = match Self::extension_criticality(cert, oid::BASIC_CONSTRAINTS)? {
            Some(critical) => critical,
            None => return Ok(None),
        };
        let path_len_constraint = cert
            .pathlen()
            .map(usize::try_from)
            .transpose()
            .map_err(|_| "pathLenConstraint does not fit usize")?;
        let flags = unsafe { X509_get_extension_flags(cert.as_ptr()) };

        Ok(Some(super::BasicConstraints {
            critical,
            ca: flags & EXFLAG_CA != 0,
            path_len_constraint,
        }))
    }

    fn key_usage(cert: &Self::Certificate) -> Result<Option<super::KeyUsage>> {
        if Self::extension_criticality(cert, oid::KEY_USAGE)?.is_none() {
            return Ok(None);
        }
        let key_usage = unsafe { X509_get_key_usage(cert.as_ptr()) };

        Ok(Some(super::KeyUsage {
            key_cert_sign: key_usage & X509v3_KU_KEY_CERT_SIGN != 0,
        }))
    }

    fn extension_criticality(cert: &Self::Certificate, oid: &str) -> Result<Option<bool>> {
        let oid = Asn1Object::from_str(oid)
            .map_err(|e| format!("Invalid extension OID {}: {:?}", oid, e))?;

        unsafe {
            let index = X509_get_ext_by_OBJ(cert.as_ptr(), oid.as_ptr(), -1);
            if index == -1 {
                return Ok(None);
            }

            let extension = X509_get_ext(cert.as_ptr(), index);
            if extension.is_null() {
                return Err("OpenSSL returned null extension pointer".into());
            }

            Ok(Some(X509_EXTENSION_get_critical(extension) != 0))
        }
    }

    fn critical_extension_oids(cert: &Self::Certificate) -> Vec<String> {
        let count = unsafe { X509_get_ext_count(cert.as_ptr()) };
        if count <= 0 {
            return Vec::new();
        }

        (0..count)
            .filter_map(|index| {
                let extension = unsafe { X509_get_ext(cert.as_ptr(), index) };
                if extension.is_null() {
                    return None;
                }

                let critical = unsafe { X509_EXTENSION_get_critical(extension) != 0 };
                if !critical {
                    return None;
                }

                let object = unsafe { X509_EXTENSION_get_object(extension) };
                if object.is_null() {
                    return None;
                }

                Some(unsafe { Asn1ObjectRef::from_ptr(object) }.to_string())
            })
            .collect()
    }
}

mod oid {
    /// RFC 5280 section 4.2.1.9: id-ce-basicConstraints OBJECT IDENTIFIER ::= { id-ce 19 }.
    pub const BASIC_CONSTRAINTS: &str = "2.5.29.19";
    /// RFC 5280 section 4.2.1.3: id-ce-keyUsage OBJECT IDENTIFIER ::= { id-ce 15 }.
    pub const KEY_USAGE: &str = "2.5.29.15";
    /// RFC 5280 section 4.2.1.6: id-ce-subjectAltName OBJECT IDENTIFIER ::= { id-ce 17 }.
    pub const SUBJECT_ALT_NAME: &str = "2.5.29.17";
    /// RFC 5280 section 4.2.1.12: id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }.
    pub const EXTENDED_KEY_USAGE: &str = "2.5.29.37";
}

fn dotted_oid(oid: &Asn1ObjectRef) -> Result<String> {
    let length = unsafe { OBJ_obj2txt(std::ptr::null_mut(), 0, oid.as_ptr(), 1) };
    if length < 0 {
        return Err("OpenSSL failed to determine OID text length".into());
    }

    let mut output = vec![0_u8; length as usize + 1];
    let written = unsafe {
        OBJ_obj2txt(
            output.as_mut_ptr().cast(),
            output
                .len()
                .try_into()
                .map_err(|_| "OID text buffer exceeds OpenSSL integer range")?,
            oid.as_ptr(),
            1,
        )
    };
    if written != length {
        return Err("OpenSSL returned an inconsistent OID text length".into());
    }
    output.truncate(written as usize);
    let oid = String::from_utf8(output)?;
    ensure_shared_oid_range(&oid)?;
    Ok(oid)
}

fn directory_string(value: &openssl::asn1::Asn1StringRef) -> Result<String> {
    let bytes = value.as_slice();
    let string = match unsafe { ASN1_STRING_type(value.as_ptr()) } {
        V_ASN1_PRINTABLESTRING => {
            if !bytes.iter().copied().all(is_printable_string_character) {
                return Err("Invalid PrintableString character in distinguished name".into());
            }
            std::str::from_utf8(bytes)?
        }
        V_ASN1_UTF8STRING => std::str::from_utf8(bytes)?,
        V_ASN1_IA5STRING => {
            if !bytes.is_ascii() {
                return Err("Invalid IA5String character in distinguished name".into());
            }
            std::str::from_utf8(bytes)?
        }
        tag => {
            return Err(format!("Unsupported distinguished-name string tag {tag}").into());
        }
    };
    Ok(string.to_owned())
}

fn is_printable_string_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b' ' | b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
        )
}

/// # Safety
///
/// `nid` must identify an extension decoded by OpenSSL as `STACK_OF(T)`.
unsafe fn decoded_extension_stack<T>(
    cert: &Certificate,
    nid: c_int,
    name: &str,
) -> Result<Option<Stack<T>>>
where
    T: openssl::stack::Stackable,
{
    let mut status = -1;
    let stack = X509_get_ext_d2i(cert.as_ptr(), nid, &mut status, std::ptr::null_mut());
    if stack.is_null() {
        return match status {
            -1 => Ok(None),
            -2 => Err(format!("Certificate contains duplicate {name} extensions").into()),
            _ => Err(format!("OpenSSL failed to decode {name}").into()),
        };
    }
    Ok(Some(Stack::from_ptr(stack.cast())))
}

fn decode_general_name(name: &GeneralNameRef) -> Result<GeneralName> {
    let tag = unsafe { (*name.as_ptr()).type_ };
    Ok(match tag {
        GEN_OTHERNAME => GeneralName::OtherName(general_name_der(name)?),
        GEN_EMAIL => GeneralName::Rfc822Name(ia5_string(name.email(), "rfc822Name")?),
        GEN_DNS => GeneralName::DnsName(ia5_string(name.dnsname(), "dNSName")?),
        GEN_X400 => GeneralName::X400Address(general_name_der(name)?),
        GEN_DIRNAME => GeneralName::DirectoryName(general_name_der(name)?),
        GEN_EDIPARTY => GeneralName::EdiPartyName(general_name_der(name)?),
        GEN_URI => GeneralName::UniformResourceIdentifier(ia5_string(
            name.uri(),
            "uniformResourceIdentifier",
        )?),
        GEN_IPADD => {
            let bytes = name
                .ipaddress()
                .ok_or("OpenSSL returned an invalid iPAddress")?;
            if !matches!(bytes.len(), 4 | 16) {
                return Err(format!("Invalid iPAddress GeneralName length {}", bytes.len()).into());
            }
            GeneralName::IpAddress(bytes.to_vec())
        }
        GEN_RID => {
            let object: *mut openssl_sys::ASN1_OBJECT = unsafe { (*name.as_ptr()).d.cast() };
            if object.is_null() {
                return Err("OpenSSL returned a null registeredID".into());
            }
            GeneralName::RegisteredId(dotted_oid(unsafe { Asn1ObjectRef::from_ptr(object) })?)
        }
        _ => {
            let der = general_name_der(name).unwrap_or_default();
            return Err(format!(
                "Invalid GeneralName tag {tag}, DER {}",
                crate::hex::to_hex(&der)
            )
            .into());
        }
    })
}

fn ia5_string(value: Option<&str>, name: &str) -> Result<String> {
    let value = value.ok_or_else(|| format!("OpenSSL returned an invalid {name}"))?;
    if !value.is_ascii() {
        return Err(format!("Non-ASCII {name}").into());
    }
    Ok(value.to_owned())
}

fn encoded_stack_der<T>(
    stack: &Stack<T>,
    encode: unsafe extern "C" fn(*const T::StackType, *mut *mut u8) -> c_int,
    name: &str,
) -> Result<Vec<u8>>
where
    T: openssl::stack::Stackable,
{
    let length = unsafe { encode(stack.as_ptr(), std::ptr::null_mut()) };
    if length <= 0 {
        return Err(format!("OpenSSL failed to determine {name} DER length").into());
    }
    let mut der = vec![0_u8; length as usize];
    let mut output = der.as_mut_ptr();
    let written = unsafe { encode(stack.as_ptr(), &mut output) };
    let expected_end = unsafe { der.as_mut_ptr().add(der.len()) };
    if written != length || output != expected_end {
        return Err(format!("OpenSSL returned an inconsistent {name} DER length").into());
    }
    Ok(der)
}

fn ensure_canonical_extension(
    cert: &Certificate,
    oid: &str,
    encoded: Vec<u8>,
    name: &str,
) -> Result<()> {
    let original = Crypto::get_extension_value_by_oid(cert, oid)?
        .ok_or_else(|| format!("OpenSSL decoded an absent {name} extension"))?;
    if original != encoded {
        return Err(format!("{name} is not canonically DER encoded").into());
    }
    Ok(())
}

fn ensure_shared_oid_range(oid: &str) -> Result<()> {
    let arcs = oid
        .split('.')
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| "OpenSSL returned an OID outside the shared backend range")?;
    if arcs.len() < 3 {
        return Err(format!("OID {oid} is outside the shared backend range").into());
    }
    let unsupported_arc = arcs[2..]
        .iter()
        .any(|arc| *arc >= (1 << 28) && arc & 0x70 != 0);
    if arcs[0] > 2
        || arcs[1] > 39
        || unsupported_arc
        || !(3..=39).contains(
            &(1 + arcs[2..]
                .iter()
                .map(|arc| {
                    let bits = u32::BITS - arc.leading_zeros();
                    usize::max(1, bits.div_ceil(7) as usize)
                })
                .sum::<usize>()),
        )
    {
        return Err(format!("OID {oid} is outside the shared backend range").into());
    }
    Ok(())
}

fn validate_subject_name_der(der: &[u8]) -> Result<usize> {
    let (tag, mut sequence, rest) = der_element(der)?;
    if tag != 0x30 || !rest.is_empty() {
        return Err("Certificate subject is not a DER SEQUENCE".into());
    }

    let mut count = 0;
    while !sequence.is_empty() {
        let (tag, mut set, remaining) = der_element(sequence)?;
        if tag != 0x31 || set.is_empty() {
            return Err("Certificate subject contains an invalid or empty RDN".into());
        }
        while !set.is_empty() {
            let (tag, _, remaining_set) = der_element(set)?;
            if tag != 0x30 {
                return Err("Certificate subject contains an invalid attribute".into());
            }
            set = remaining_set;
        }
        count += 1;
        sequence = remaining;
    }
    Ok(count)
}

fn name_entry_der(entry: &openssl::x509::X509NameEntryRef) -> Result<Vec<u8>> {
    let length = unsafe { i2d_X509_NAME_ENTRY(entry.as_ptr(), std::ptr::null_mut()) };
    if length <= 0 {
        return Err("OpenSSL failed to determine name-entry DER length".into());
    }
    let mut der = vec![0_u8; length as usize];
    let mut output = der.as_mut_ptr();
    let written = unsafe { i2d_X509_NAME_ENTRY(entry.as_ptr(), &mut output) };
    let expected_end = unsafe { der.as_mut_ptr().add(der.len()) };
    if written != length || output != expected_end {
        return Err("OpenSSL returned an inconsistent name-entry DER length".into());
    }
    Ok(der)
}

fn der_element(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let (&tag, input) = input
        .split_first()
        .ok_or("Truncated DER element in certificate subject")?;
    let (&first_length, input) = input
        .split_first()
        .ok_or("Truncated DER length in certificate subject")?;
    let (length, input) = if first_length < 0x80 {
        (first_length as usize, input)
    } else {
        let length_bytes = (first_length & 0x7f) as usize;
        if length_bytes == 0
            || length_bytes > std::mem::size_of::<usize>()
            || input.len() < length_bytes
            || input[0] == 0
        {
            return Err("Invalid DER length in certificate subject".into());
        }
        let length = input[..length_bytes]
            .iter()
            .fold(0usize, |length, byte| (length << 8) | *byte as usize);
        if length < 0x80 {
            return Err("Non-minimal DER length in certificate subject".into());
        }
        (length, &input[length_bytes..])
    };
    if input.len() < length {
        return Err("Truncated DER value in certificate subject".into());
    }
    Ok((tag, &input[..length], &input[length..]))
}

fn general_name_der(name: &GeneralNameRef) -> Result<Vec<u8>> {
    let length = unsafe { i2d_GENERAL_NAME(name.as_ptr(), std::ptr::null_mut()) };
    if length <= 0 {
        return Err("OpenSSL failed to determine GeneralName DER length".into());
    }
    let mut der = vec![0_u8; length as usize];
    let mut output = der.as_mut_ptr();
    let written = unsafe { i2d_GENERAL_NAME(name.as_ptr(), &mut output) };
    let expected_end = unsafe { der.as_mut_ptr().add(der.len()) };
    if written != length || output != expected_end {
        return Err("OpenSSL returned an inconsistent GeneralName DER length".into());
    }
    Ok(der)
}

impl CryptoBackend for Crypto {
    type Key = Key;
    type Signature = Signature;

    fn digest(algorithm: DigestAlgorithm, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(hash(message_digest(algorithm), bytes)?.to_vec())
    }

    fn verify_signature(
        key: &Self::Key,
        signature: &Self::Signature,
        signed_bytes: &[u8],
    ) -> Result<()> {
        let signature_algorithm = signature.algorithm();
        key.verification
            .ensure_signature_algorithm(signature_algorithm)?;
        let signature = signature.as_openssl_bytes();
        let mut verifier = key.verification.verifier(&key.key, signature_algorithm)?;

        match verifier.verify_oneshot(signature, signed_bytes) {
            Ok(true) => Ok(()),
            Ok(false) => Err(key.verification.failure_message().into()),
            Err(e) => Err(Box::new(e)),
        }
    }

    fn verify_chain(
        trusted_cert: &Certificate,
        untrusted_chain: &[&Certificate],
        leaf: &Certificate,
        unix_time: Option<std::time::Duration>,
    ) -> Result<()> {
        let mut issuer = trusted_cert;
        for subject in untrusted_chain.iter().copied().chain(std::iter::once(leaf)) {
            if !Self::issuer_name_matches_subject(subject, issuer)? {
                return Err("Certificate chain is not in issuer-to-subject order".into());
            }
            let issuer_public_key = issuer.public_key()?;
            if !subject.verify(&issuer_public_key)? {
                return Err("Certificate signature verification failed".into());
            }
            issuer = subject;
        }

        let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
        store_builder.add_cert(trusted_cert.to_owned())?;
        store_builder.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
        if let Some(unix_time) = unix_time {
            let mut params = X509VerifyParam::new()?;
            let unix_time = unix_time
                .as_secs()
                .try_into()
                .map_err(|_| "Unix time does not fit OpenSSL time_t")?;
            params.set_time(unix_time);
            store_builder.set_param(&params)?;
        }
        let store = store_builder.build();
        let mut ctx = openssl::x509::X509StoreContext::new()?;
        let mut chain = Stack::<Certificate>::new()?;
        for cert in untrusted_chain {
            chain.push((*cert).to_owned())?;
        }
        match ctx.init(&store, leaf, &chain, |c| c.verify_cert()) {
            Ok(true) => Ok(()),
            Ok(false) => Err("Certificate verification failed".into()),
            Err(e) => Err(Box::new(e)),
        }
    }
}

impl Key {
    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        self.verification.algorithm()
    }
}

impl OpenSslKeyVerification {
    fn from_key_algorithm(key: &PKey<Public>, algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(algorithm) => {
                let key = key
                    .ec_key()
                    .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;
                let curve_name = key
                    .group()
                    .curve_name()
                    .ok_or("ECDSA public key must use a named curve")?;
                let expected_curve_name = ec_curve_nid(algorithm);
                if curve_name != expected_curve_name {
                    return Err(format!(
                        "ECDSA public key curve does not match algorithm {}",
                        algorithm.name()
                    )
                    .into());
                }

                Ok(Self::Ecdsa { algorithm })
            }
            SignatureKeyAlgorithm::RsaPss(algorithm) => {
                key.rsa()
                    .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;
                Ok(Self::RsaPss { algorithm })
            }
            SignatureKeyAlgorithm::RsaPkcs1v15(algorithm) => {
                key.rsa()
                    .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;
                Ok(Self::RsaPkcs1v15 { algorithm })
            }
        }
    }

    fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Self::Ecdsa { algorithm } => SignatureKeyAlgorithm::Ec(*algorithm),
            Self::RsaPss { algorithm } => SignatureKeyAlgorithm::RsaPss(*algorithm),
            Self::RsaPkcs1v15 { algorithm } => SignatureKeyAlgorithm::RsaPkcs1v15(*algorithm),
        }
    }

    fn ensure_signature_algorithm(&self, actual: SignatureKeyAlgorithm) -> Result<()> {
        let expected = self.algorithm();
        if !compatible_key_and_signature(expected, actual) {
            return Err(format!(
                "Signature algorithm {actual:?} does not match key algorithm {expected:?}"
            )
            .into());
        }

        Ok(())
    }

    fn verifier<'key>(
        &self,
        key: &'key PKey<Public>,
        signature_algorithm: SignatureKeyAlgorithm,
    ) -> Result<OpenSslVerifier<'key>> {
        let digest = message_digest(signature_algorithm.digest());
        let mut verifier = OpenSslVerifier::new(digest, key)?;

        if matches!(signature_algorithm, SignatureKeyAlgorithm::RsaPss(_)) {
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            verifier.set_rsa_mgf1_md(digest)?;
        } else if matches!(signature_algorithm, SignatureKeyAlgorithm::RsaPkcs1v15(_)) {
            verifier.set_rsa_padding(Padding::PKCS1)?;
        }

        Ok(verifier)
    }

    fn failure_message(&self) -> &'static str {
        match self {
            Self::Ecdsa { algorithm: _ } => "ECDSA signature verification failed",
            Self::RsaPss { algorithm: _ } => "RSA-PSS signature verification failed",
            Self::RsaPkcs1v15 { algorithm: _ } => "RSA PKCS#1 v1.5 signature verification failed",
        }
    }
}

impl Signature {
    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Self::Ecdsa { algorithm, .. } => SignatureKeyAlgorithm::Ec(*algorithm),
            Self::RsaPss { algorithm, .. } => SignatureKeyAlgorithm::RsaPss(*algorithm),
            Self::RsaPkcs1v15 { algorithm, .. } => SignatureKeyAlgorithm::RsaPkcs1v15(*algorithm),
        }
    }

    fn as_openssl_bytes(&self) -> &[u8] {
        match self {
            Self::Ecdsa { der, .. } => der,
            Self::RsaPss { raw, .. } => raw,
            Self::RsaPkcs1v15 { raw, .. } => raw,
        }
    }
}

fn ec_component_from_bytes(
    name: &str,
    component: &[u8],
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<BigNum> {
    let max_len = algorithm.scalar_byte_len();
    if component.is_empty() || component.len() > max_len {
        return Err(format!(
            "Invalid ECDSA {} {name} component length: expected 1..={}, got {}",
            algorithm.name(),
            max_len,
            component.len()
        )
        .into());
    }

    Ok(BigNum::from_slice(component)?)
}

fn message_digest(digest: DigestAlgorithm) -> MessageDigest {
    match digest {
        DigestAlgorithm::Sha256 => MessageDigest::sha256(),
        DigestAlgorithm::Sha384 => MessageDigest::sha384(),
        DigestAlgorithm::Sha512 => MessageDigest::sha512(),
    }
}

fn ec_curve_nid(algorithm: EcSignatureKeyAlgorithm) -> Nid {
    match algorithm {
        EcSignatureKeyAlgorithm::P256 => Nid::X9_62_PRIME256V1,
        EcSignatureKeyAlgorithm::P384 => Nid::SECP384R1,
        EcSignatureKeyAlgorithm::P521 => Nid::SECP521R1,
    }
}
