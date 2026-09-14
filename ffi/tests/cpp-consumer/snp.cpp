// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Consumer tests for the C++ SNP wrapper (tav/snp.hpp), driven through
// tav::snp::Report. These check that the wrapper faithfully translates the C
// ABI (every accessor, ownership, and error handling), not attestation
// verification correctness, which is covered by the Rust unit tests and the
// C consumer tests in ffi/tests/c-consumer.

#include "../c-consumer/support.h"

#include <tav/snp.hpp>
#include <tav/utils.hpp>

#include <type_traits>

using namespace tav_test;

// Non-copyable ownership is what keeps one handle from being freed twice.
static_assert(!std::is_copy_constructible_v<tav::snp::Report>);
static_assert(!std::is_copy_assignable_v<tav::snp::Report>);
static_assert(std::is_move_constructible_v<tav::snp::Report>);
static_assert(std::is_move_assignable_v<tav::snp::Report>);

namespace {

struct MilanInputs {
    std::vector<uint8_t> report;
    std::vector<uint8_t> ark;
    std::vector<uint8_t> ask;
    std::vector<uint8_t> vcek;
};

MilanInputs load_milan_inputs() {
    return MilanInputs{
        read_file("attestation/tests/test_data/milan_attestation_report.bin"),
        read_file("attestation/src/pinned_arks/milan_ark.pem"),
        read_file("attestation/tests/test_data/milan_ask.pem"),
        read_file("attestation/tests/test_data/milan_vcek.pem"),
    };
}

std::string hex(std::span<const uint8_t> bytes) {
    return hex_encode(bytes.data(), bytes.size());
}

} // namespace

TEST_CASE("snp.hpp: every accessor exposes the golden Milan value") {
    MilanInputs in = load_milan_inputs();

    tav::snp::Report report = tav::snp::Report::verify(in.report, in.ark, in.ask, in.vcek);

    // Golden values mirror ffi/tests/c-consumer/snp.cpp, which are in turn
    // taken from demos/c-ffi/test-data/milan-output.golden.txt.

    // Scalar accessors.
    CHECK(report.version() == 3);
    CHECK(report.guest_svn() == 2);
    CHECK(report.policy() == 0x3001full);
    CHECK(report.policy_abi_minor() == 31);
    CHECK(report.policy_abi_major() == 0);
    CHECK(report.policy_smt());
    CHECK_FALSE(report.policy_migrate_ma());
    CHECK_FALSE(report.policy_debug());
    CHECK_FALSE(report.policy_single_socket());
    CHECK_FALSE(report.policy_cxl_allow());
    CHECK_FALSE(report.policy_mem_aes_256_xts());
    CHECK_FALSE(report.policy_rapl_dis());
    CHECK_FALSE(report.policy_ciphertext_hiding_dram());
    CHECK_FALSE(report.policy_page_swap_disable());
    CHECK(report.vmpl() == 0);
    CHECK(report.signature_algo() == 1);
    CHECK(report.platform_info() == 0x25ull);
    CHECK(report.flags() == 0x0u);
    CHECK_FALSE(report.flags_author_key_en());
    CHECK_FALSE(report.flags_mask_chip_key());
    CHECK(report.flags_signing_key() == 0);
    CHECK(report.cpuid_fam_id() == 25);
    CHECK(report.cpuid_mod_id() == 1);
    CHECK(report.cpuid_step() == 1);
    CHECK(report.current_build() == 29);
    CHECK(report.current_minor() == 55);
    CHECK(report.current_major() == 1);
    CHECK(report.committed_build() == 29);
    CHECK(report.committed_minor() == 55);
    CHECK(report.committed_major() == 1);

    // Borrowed byte-slice accessors.
    CHECK(hex(report.family_id()) == "01000000000000000000000000000000");
    CHECK(hex(report.image_id()) == "02000000000000000000000000000000");
    CHECK(hex(report.platform_version()) == "04000000000018db");
    CHECK(hex(report.report_data()) ==
          "0000000000000000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000000000000000000000");
    CHECK(hex(report.measurement()) ==
          "5feee30d6d7e1a29f403d70a4198237ddfb13051a2d6976439487c609388ed7f9818"
          "9887920ab2fa0096903a0c23fca1");
    CHECK(hex(report.host_data()) ==
          "4f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d10");
    CHECK(hex(report.id_key_digest()) ==
          "0ad79ceb0b648b0e6a90d8aa9f6ea24c33a968b6632085353145e8b19a4741a2dab9"
          "ba342e13be4fc0d225e889cc1a58");
    CHECK(hex(report.author_key_digest()) ==
          "00000000000000000000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000");
    CHECK(hex(report.report_id()) ==
          "5e01036273418d910bdca3f5cb9c7d849e88e2141483eb6cc9afd794ffbbbcbc");
    CHECK(hex(report.report_id_ma()) ==
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    CHECK(hex(report.reported_tcb()) == "04000000000018db");
    CHECK(hex(report.chip_id()) ==
          "4ffb5cb4fd594f3fee6528fc3fb10370bb38abe89dcd5ba2cf0ab6a11df2ca282add"
          "516bef45a890a8c9f9732bdca68f9f3f16c42e846030a800295dbeb19ba5");
    CHECK(hex(report.committed_tcb()) == "04000000000018db");
    CHECK(hex(report.launch_tcb()) == "04000000000018db");
    CHECK(hex(report.signature_r()) ==
          "c4c97ce68cfa7fe769a569fc55cee5ad38b238a4e1db928436a006b76e9a5885851d"
          "13c88892e5ffd93f3e1cf853f3b7000000000000000000000000000000000000000"
          "000000000");
    CHECK(hex(report.signature_s()) ==
          "1e739e881fffadfeab34e3fb205ff0a5d8992496d0fb390a18baa725de048253e664"
          "e519b8f38309061b4af2a3e69f53000000000000000000000000000000000000000"
          "000000000");
}

TEST_CASE("snp.hpp: a tampered report throws tav::Exception and leaves no handle") {
    MilanInputs in = load_milan_inputs();
    // Corrupt the measurement region so the AMD signature no longer matches.
    in.report.at(0x90) ^= 0xff;

    CHECK_THROWS_AS(
        (void)tav::snp::Report::verify(in.report, in.ark, in.ask, in.vcek),
        tav::Exception);

    try {
        (void)tav::snp::Report::verify(in.report, in.ark, in.ask, in.vcek);
        FAIL("expected tav::Exception");
    } catch (const tav::Exception &error) {
        CHECK(error.code() == tav::ErrorCode::SNP_SIGNATURE_VERIFICATION_ERROR);
        CHECK(std::string(error.what()).size() > 0);
    }
}

TEST_CASE("snp.hpp: unverified bytes expose report fields without authenticating them") {
    MilanInputs in = load_milan_inputs();
    in.report.at(0x90) ^= 0xff;

    tav::snp::Report report = tav::snp::Report::from_unverified_bytes(in.report);
    CHECK(hex(report.measurement()).rfind("a0", 0) == 0);
}

TEST_CASE("snp.hpp: invalid unverified report length throws tav::Exception") {
    MilanInputs in = load_milan_inputs();
    in.report.pop_back();

    try {
        (void)tav::snp::Report::from_unverified_bytes(in.report);
        FAIL("expected tav::Exception");
    } catch (const tav::Exception &error) {
        CHECK(error.code() == tav::ErrorCode::INVALID_ARGUMENT);
        CHECK(std::string(error.what()) ==
              "Invalid attestation report: expected 1184 bytes, got 1183");
    }
}

TEST_CASE("snp.hpp: moving a Report transfers ownership") {
    MilanInputs in = load_milan_inputs();

    tav::snp::Report report = tav::snp::Report::from_unverified_bytes(in.report);
    tav::snp::Report moved = std::move(report);
    CHECK(moved.version() == 3);
}
