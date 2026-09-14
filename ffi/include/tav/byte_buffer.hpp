// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <tav/byte_buffer.h>

#include <cstdint>
#include <span>
#include <utility>

namespace tav
{
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
}
