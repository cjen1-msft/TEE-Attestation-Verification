// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// RFC 5280 §4.2.1.12: id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }.
pub(crate) const EXTENDED_KEY_USAGE: &str = "2.5.29.37";
/// OID contents (without tag and length) for anyExtendedKeyUsage (2.5.29.37.0).
pub(crate) const ANY_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

pub(crate) fn encode_purpose_oid(purpose: &str) -> super::Result<Vec<u8>> {
    let invalid_oid = "Invalid dotted-decimal purpose OID";
    let mut arcs = purpose.split('.').map(|arc| {
        if arc.is_empty() || !arc.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid_oid);
        }
        arc.parse::<u64>().map_err(|_| invalid_oid)
    });
    let first = arcs.next().ok_or(invalid_oid)??;
    let second = arcs.next().ok_or(invalid_oid)??;
    if first > 2 || (first < 2 && second > 39) {
        return Err(invalid_oid.into());
    }
    let root = second.checked_add(40 * first).ok_or(invalid_oid)?;

    let mut encoded = Vec::new();
    for arc in std::iter::once(Ok(root)).chain(arcs) {
        // Encode the base-128 bytes of each arc from least to most significant,
        // then put that arc's bytes in DER order.
        let mut arc = arc?;
        let start = encoded.len();
        encoded.push((arc & 0x7f) as u8);
        while arc >= 128 {
            arc >>= 7;
            encoded.push((arc & 0x7f) as u8 | 0x80);
        }
        encoded[start..].reverse();
    }
    if encoded == ANY_EXTENDED_KEY_USAGE {
        return Err("anyExtendedKeyUsage is not a specific intended purpose".into());
    }
    Ok(encoded)
}
