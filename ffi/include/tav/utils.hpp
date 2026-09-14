// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// RAII/exception wrapper over the shared C ABI error and byte-buffer types in
// <tav/utils.h>. This is the supported interface; the C header is retained
// for consumers that need the raw ABI.
//
// Every public C ABI function documented as returning an owned TavError* on
// failure is wrapped here to instead throw tav::Exception, carrying the
// TavErrorCode and message from the failed TavError before freeing it.
//
// TavByteBuffer* out-parameters are wrapped as tav::ByteBuffer, an
// independently owned buffer that releases its handle on destruction and
// exposes its contents as a std::span.

#pragma once

#include <tav/utils.h>

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

namespace tav
{
/// Stable error codes returned by the native TAV ABI.
enum class ErrorCode : int
{
    OK = TAV_ERROR_OK,
    INVALID_ARGUMENT = TAV_ERROR_INVALID_ARGUMENT,
    IS_NULL = TAV_ERROR_IS_NULL,
    PANIC = TAV_ERROR_PANIC,

    SNP_UNSUPPORTED_PROCESSOR = TAV_ERROR_SNP_UNSUPPORTED_PROCESSOR,
    SNP_INVALID_ROOT_CERTIFICATE = TAV_ERROR_SNP_INVALID_ROOT_CERTIFICATE,
    SNP_CERTIFICATE_CHAIN_ERROR = TAV_ERROR_SNP_CERTIFICATE_CHAIN_ERROR,
    SNP_SIGNATURE_VERIFICATION_ERROR = TAV_ERROR_SNP_SIGNATURE_VERIFICATION_ERROR,
    SNP_TCB_VERIFICATION_ERROR = TAV_ERROR_SNP_TCB_VERIFICATION_ERROR,

    COSE_CBOR = TAV_ERROR_COSE_CBOR,
    COSE_UNEXPECTED_TYPE = TAV_ERROR_COSE_UNEXPECTED_TYPE,
    COSE_UNSUPPORTED_ALGORITHM = TAV_ERROR_COSE_UNSUPPORTED_ALGORITHM,
    COSE_KEY_IMPORT = TAV_ERROR_COSE_KEY_IMPORT,
    COSE_VERIFICATION = TAV_ERROR_COSE_VERIFICATION,

    CACI_COSE = TAV_ERROR_CACI_COSE,
    CACI_CERTIFICATE = TAV_ERROR_CACI_CERTIFICATE,
    CACI_DID_X509 = TAV_ERROR_CACI_DID_X509,
    CACI_SIGNATURE = TAV_ERROR_CACI_SIGNATURE,
    CACI_MEASUREMENT = TAV_ERROR_CACI_MEASUREMENT,
    CACI_POLICY = TAV_ERROR_CACI_POLICY,
};

/// Thrown for every TavError the C ABI reports.
class Exception : public std::runtime_error
{
public:
    Exception(ErrorCode code, const std::string& what) :
      std::runtime_error(what),
      code_(code)
    {}

    [[nodiscard]] ErrorCode code() const
    {
        return code_;
    }

private:
    ErrorCode code_;
};

/// An owned byte buffer returned by a public C ABI function.
///
/// Moving transfers the handle and empties the source. bytes() returns a view
/// borrowed from this buffer; it must not outlive the ByteBuffer.
class ByteBuffer
{
public:
    ByteBuffer() = default;
    ByteBuffer(const ByteBuffer&) = delete;
    ByteBuffer& operator=(const ByteBuffer&) = delete;

    ByteBuffer(ByteBuffer&& other) noexcept :
      handle_(std::exchange(other.handle_, nullptr))
    {}

    ByteBuffer& operator=(ByteBuffer&& other) noexcept
    {
        if (this != &other)
        {
            tav_byte_buffer_free(handle_);
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    ~ByteBuffer()
    {
        tav_byte_buffer_free(handle_);
    }

    /// True once the handle has been moved out.
    [[nodiscard]] bool empty() const
    {
        return handle_ == nullptr;
    }

    [[nodiscard]] std::span<const uint8_t> bytes() const
    {
        return {tav_byte_buffer_data(handle_), tav_byte_buffer_len(handle_)};
    }

    /// Adopts a handle a C ABI function wrote through an out-parameter.
    static ByteBuffer adopt(TavByteBuffer* handle)
    {
        return ByteBuffer(handle);
    }

private:
    explicit ByteBuffer(TavByteBuffer* handle) : handle_(handle) {}

    TavByteBuffer* handle_ = nullptr;
};

/// Consumes a TavError* a C ABI function returned: does nothing if null,
/// otherwise frees it and throws the equivalent Exception.
inline void check(TavError* error)
{
    if (error == nullptr)
    {
        return;
    }
    const ErrorCode code = static_cast<ErrorCode>(tav_error_code(error));
    const std::string message = tav_error_message(error);
    tav_error_free(error);
    throw Exception(code, message);
}
}
