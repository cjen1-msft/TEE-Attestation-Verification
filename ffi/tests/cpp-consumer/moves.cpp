// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "../c-consumer/support.h"

#include <tav/cbor.hpp>
#include <tav/cose.h>
#include <tav/snp.hpp>
#include <tav/utils.hpp>

#include <memory>
#include <type_traits>

namespace {

template <typename Make, typename Read>
void check_handle_moves(Make make, Read read) {
    using T = decltype(make(1));
    static_assert(!std::is_copy_constructible_v<T>);
    static_assert(!std::is_copy_assignable_v<T>);
    static_assert(std::is_nothrow_move_constructible_v<T>);
    static_assert(std::is_nothrow_move_assignable_v<T>);

    auto source = make(1);
    REQUIRE_FALSE(source.empty());
    auto& alias = source;
    CHECK(&(source = std::move(alias)) == &source);
    REQUIRE_FALSE(source.empty());
    CHECK(read(source) == 1);

    auto moved = std::move(source);
    CHECK(source.empty());
    REQUIRE_FALSE(moved.empty());
    CHECK(read(moved) == 1);

    auto destination = make(2);
    CHECK(read(destination) == 2);
    CHECK(&(destination = std::move(moved)) == &destination);
    CHECK(moved.empty());
    REQUIRE_FALSE(destination.empty());
    CHECK(read(destination) == 1);

    // Moving from an empty source clears an occupied destination.
    destination = std::move(source);
    CHECK(source.empty());
    CHECK(destination.empty());
    auto empty = std::move(source);
    CHECK(source.empty());
    CHECK(empty.empty());
    CHECK(&(source = std::move(alias)) == &source);
    CHECK(source.empty());

    {
        auto replacement = make(3);
        source = std::move(replacement);
        CHECK(replacement.empty());
    }
    REQUIRE_FALSE(source.empty());
    CHECK(read(source) == 3);
}

template <typename E, typename Code, typename ReadCode>
void check_error_moves(Code first, Code second, ReadCode read_code) {
    static_assert(std::is_move_constructible_v<E>);
    static_assert(std::is_move_assignable_v<E>);
    E source(first, "first error");
    auto& alias = source;
    CHECK(&(source = std::move(alias)) == &source);
    CHECK(read_code(source) == first);
    // The standard library controls the moved-from runtime_error message.
    // Reassign before testing its contents.
    source = E(first, "first error");
    E moved(std::move(source));
    CHECK(read_code(moved) == first);
    CHECK(std::string(moved.what()) == "first error");

    E destination(second, "second error");
    destination = std::move(moved);
    CHECK(read_code(destination) == first);
    CHECK(std::string(destination.what()) == "first error");
    source = E(second, "reused error");
    CHECK(read_code(source) == second);
    CHECK(std::string(source.what()) == "reused error");
}

} // namespace

TEST_CASE("C++ moves: Report") {
    check_handle_moves(
        [](uint8_t version) {
            auto bytes = tav_test::read_file(
                "attestation/tests/test_data/milan_attestation_report.bin");
            bytes[0] = version;
            return tav::snp::Report::from_unverified_bytes(bytes);
        },
        [](const tav::snp::Report& report) { return report.version(); });
}

TEST_CASE("C++ moves: ByteBuffer") {
    check_handle_moves(
        [](uint8_t byte) {
            TavCborValue* raw = nullptr;
            tav::check(tav_cbor_value_from_bytes(&byte, 1, &raw));
            std::unique_ptr<TavCborValue, decltype(&tav_cbor_value_free)> value(
                raw, tav_cbor_value_free);
            TavByteBuffer* buffer = nullptr;
            tav::check(tav_cbor_value_to_bytes(value.get(), &buffer));
            return tav::ByteBuffer::adopt(buffer);
        },
        [](const tav::ByteBuffer& buffer) {
            REQUIRE(buffer.bytes().size() == 1);
            return buffer.bytes()[0];
        });
}

TEST_CASE("C++ moves: CBOR Value") {
    check_handle_moves(
        [](int value) { return tav::cbor::make_signed(value); },
        [](const tav::cbor::Value& value) { return value.as_signed(); });
}

TEST_CASE("C++ moves: Exception") {
    check_error_moves<tav::Exception>(
        tav::ErrorCode::IS_NULL, tav::ErrorCode::INVALID_ARGUMENT,
        [](const tav::Exception& error) { return error.code(); });
}

TEST_CASE("C++ moves: CBOR exceptions") {
    const auto code = [](const tav::cbor::CborError& error) {
        return error.error_code();
    };
    check_error_moves<tav::cbor::CborError>(
        tav::cbor::Error::TYPE_MISMATCH, tav::cbor::Error::KEY_NOT_FOUND, code);
    check_error_moves<tav::cbor::DecodeError>(
        tav::cbor::Error::DECODE_FAILED, tav::cbor::Error::OUT_OF_BOUND, code);
    check_error_moves<tav::cbor::EncodeError>(
        tav::cbor::Error::ENCODE_FAILED, tav::cbor::Error::TYPE_MISMATCH, code);
}
