// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native readers shared by the generic ABI and the COSE compatibility ABI.
//! Errors here retain the legacy diagnostics; the generic ABI maps them to
//! its own error taxonomy at its boundary.

use crate::cbor_view::NativeCborValue;
use crate::{TavError, TavErrorCode};

pub(super) fn parse<M: cbor::Mode>(
    bytes: &[u8],
    max_depth: usize,
) -> Result<cbor::CborValue<'_>, String> {
    cbor::CborValue::parse_with_depth::<M>(bytes, super::cbor::capped(max_depth))
}

pub(super) fn serialize<M: cbor::Mode>(
    value: &NativeCborValue,
    max_depth: usize,
) -> Result<Vec<u8>, String> {
    value.to_bytes_with_depth::<M>(super::cbor::capped(max_depth))
}

fn unexpected(message: &str) -> TavError {
    TavError::new(TavErrorCode::CoseUnexpectedType, message)
}

pub(super) fn int(value: &NativeCborValue) -> Result<i64, TavError> {
    match value {
        NativeCborValue::Int(value) => Ok(*value),
        _ => Err(unexpected("value must be an int")),
    }
}

pub(super) fn simple(value: &NativeCborValue) -> Result<u8, TavError> {
    match value {
        NativeCborValue::Simple(value) => Ok(*value),
        _ => Err(unexpected("value must be simple")),
    }
}

pub(super) fn bytes<'a>(value: &'a NativeCborValue, name: &str) -> Result<&'a [u8], TavError> {
    match value {
        NativeCborValue::ByteString(value) => Ok(value),
        _ => Err(unexpected(&format!("{name} must be a byte string"))),
    }
}

pub(super) fn text(value: &NativeCborValue) -> Result<&str, TavError> {
    match value {
        NativeCborValue::TextString(value) => Ok(value),
        _ => Err(unexpected("value must be text")),
    }
}

pub(super) fn tagged(value: &NativeCborValue) -> Result<(u64, &NativeCborValue), TavError> {
    match value {
        NativeCborValue::Tagged { tag, payload } => Ok((*tag, payload)),
        _ => Err(unexpected("value must be tagged")),
    }
}

pub(super) fn map_entry(
    value: &NativeCborValue,
    index: usize,
) -> Result<(&NativeCborValue, &NativeCborValue), TavError> {
    match value {
        NativeCborValue::Map(entries) => entries
            .get(index)
            .map(|(key, value)| (key, value))
            .ok_or_else(|| {
                TavError::new(
                    TavErrorCode::CoseCbor,
                    format!("Index {index} out of bounds"),
                )
            }),
        _ => Err(unexpected("value must be a map")),
    }
}
