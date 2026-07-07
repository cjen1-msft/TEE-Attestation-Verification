// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C-ABI-specific FFI helpers: pointer/buffer marshaling built on the shared
//! [`crate::TavError`]/[`crate::TavErrorCode`] types.

use std::os::raw::c_char;

use crate::{TavError, TavErrorCode};

const NULL_ERROR_MESSAGE: &[u8] = b"null TavError pointer\0";

#[no_mangle]
pub unsafe extern "C" fn tav_error_code(error: *const TavError) -> TavErrorCode {
    if error.is_null() {
        return TavErrorCode::ErrorCodeIsNull;
    }

    unsafe { (*error).code }
}

#[no_mangle]
pub unsafe extern "C" fn tav_error_message(error: *const TavError) -> *const c_char {
    if error.is_null() {
        return NULL_ERROR_MESSAGE.as_ptr().cast();
    }

    unsafe { (*error).message.as_ptr() }
}

#[no_mangle]
pub unsafe extern "C" fn tav_error_free(error: *mut TavError) {
    if !error.is_null() {
        unsafe {
            drop(Box::from_raw(error));
        }
    }
}

/// Owned byte buffer returned by public C ABI functions.
///
/// `data` points to a library-owned allocation of `len` bytes. Release it with
/// [`tav_byte_buffer_free`], which frees the allocation and resets the buffer to
/// `{ data: NULL, len: 0 }`.
#[repr(C)]
#[derive(Debug)]
pub struct TavByteBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl TavByteBuffer {
    /// An empty buffer with a null data pointer.
    pub const fn empty() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
        }
    }

    /// Take ownership of `bytes` and expose it as a C byte buffer.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into().into_boxed_slice();
        let len = bytes.len();
        let data = Box::into_raw(bytes).cast::<u8>();
        Self { data, len }
    }
}

#[cfg(not(target_family = "wasm"))]
#[no_mangle]
pub unsafe extern "C" fn tav_byte_buffer_free(bytes: *mut TavByteBuffer) {
    if bytes.is_null() {
        return;
    }

    let bytes = unsafe { &mut *bytes };
    if !bytes.data.is_null() {
        let data = std::ptr::slice_from_raw_parts_mut(bytes.data, bytes.len);
        unsafe {
            drop(Box::from_raw(data));
        }
        bytes.data = std::ptr::null_mut();
        bytes.len = 0;
    }
}

/// Maximum size accepted for any single C ABI input buffer (1 GiB).
///
/// Bounds attacker-controlled lengths before they reach `slice::from_raw_parts`
/// and guards `count * stride` arithmetic in callers that read parallel arrays.
pub const MAX_INPUT_LEN: usize = 1024 * 1024 * 1024;

/// Borrow a caller-provided input buffer after validating its pointer and length.
///
/// # Safety
/// When `len` is non-zero, `data` must point to at least `len` readable bytes
/// that outlive `'a`.
#[cfg(not(target_family = "wasm"))]
pub unsafe fn input_bytes<'a>(
    data: *const u8,
    len: usize,
    name: &str,
    allow_empty: bool,
) -> Result<&'a [u8], TavError> {
    if len == 0 {
        if allow_empty {
            return Ok(&[]);
        }
        return Err(TavError::invalid_argument(format!("{name} is empty")));
    }
    if data.is_null() {
        return Err(TavError::invalid_argument(format!(
            "{name} pointer is null"
        )));
    }
    if len > MAX_INPUT_LEN {
        return Err(TavError::invalid_argument(format!(
            "{name} exceeds maximum input size"
        )));
    }
    Ok(unsafe { std::slice::from_raw_parts(data, len) })
}

/// Borrow a caller-provided UTF-8 input, validating pointer, length, and encoding.
///
/// # Safety
/// Same requirements as [`input_bytes`].
#[cfg(not(target_family = "wasm"))]
pub unsafe fn input_text<'a>(
    data: *const c_char,
    len: usize,
    name: &str,
    allow_empty: bool,
) -> Result<&'a str, TavError> {
    let bytes = unsafe { input_bytes(data.cast(), len, name, allow_empty) }?;
    std::str::from_utf8(bytes)
        .map_err(|error| TavError::invalid_argument(format!("{name} is not valid UTF-8: {error}")))
}

/// Validate that an out-parameter pointer is non-null.
///
/// # Safety
/// `out` must be a valid pointer to writable storage, or null.
#[cfg(not(target_family = "wasm"))]
pub unsafe fn out_ptr<T>(out: *mut T, name: &str) -> Result<(), TavError> {
    if out.is_null() {
        return Err(TavError::invalid_argument(format!(
            "{name} pointer is null"
        )));
    }
    Ok(())
}

/// Validate and reset an owned-handle out-parameter to null before fallible work.
///
/// # Safety
/// `out` must be a valid pointer to a writable handle slot, or null.
#[cfg(not(target_family = "wasm"))]
pub unsafe fn owned_out_ptr<T>(out: *mut *mut T, name: &str) -> Result<(), TavError> {
    unsafe { out_ptr(out, name) }?;
    unsafe {
        *out = std::ptr::null_mut();
    }
    Ok(())
}

/// Validate and reset a byte-buffer out-parameter to empty before fallible work.
///
/// # Safety
/// `out` must be a valid pointer to a writable [`TavByteBuffer`], or null.
#[cfg(not(target_family = "wasm"))]
pub unsafe fn byte_buffer_out_ptr(out: *mut TavByteBuffer, name: &str) -> Result<(), TavError> {
    unsafe { out_ptr(out, name) }?;
    unsafe {
        *out = TavByteBuffer::empty();
    }
    Ok(())
}
