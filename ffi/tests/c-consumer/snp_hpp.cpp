// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Consumer tests for the C++ SNP wrapper (tav/snp.hpp). These build as a
// separate C++20 executable so the C ABI tests keep their C++17 coverage.

#include "support.h"

#include <tav/snp.hpp>

#include <map>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

using namespace tav_test;
using tav::snp::AttestationReport;

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

AttestationReport verify_milan(const MilanInputs &in) {
    return AttestationReport::verify(in.report, in.ark, in.ask, in.vcek);
}

std::string hex(std::span<const uint8_t> bytes) {
    return hex_encode(bytes.data(), bytes.size());
}

} // namespace

TEST_CASE("snp.hpp: verify exposes every accessor with its golden Milan value") {
    MilanInputs in = load_milan_inputs();
    AttestationReport report = verify_milan(in);

    REQUIRE_FALSE(report.empty());

    // Golden values from demos/c-ffi/test-data/milan-output.golden.txt, which is
    // produced from the same four Milan fixtures loaded above. This exercises
    // every accessor declared in tav/snp.hpp exactly once.
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

    CHECK(hex(report.report_data()) ==
          "0000000000000000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000000000000000000000");
    CHECK(hex(report.family_id()) == "01000000000000000000000000000000");
    CHECK(hex(report.image_id()) == "02000000000000000000000000000000");
    CHECK(hex(report.platform_version()) == "04000000000018db");
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

    // Every byte accessor reports the SNP field width.
    CHECK(report.report_data().size() == 64);
    CHECK(report.family_id().size() == 16);
    CHECK(report.image_id().size() == 16);
    CHECK(report.platform_version().size() == 8);
    CHECK(report.measurement().size() == 48);
    CHECK(report.host_data().size() == 32);
    CHECK(report.id_key_digest().size() == 48);
    CHECK(report.author_key_digest().size() == 48);
    CHECK(report.report_id().size() == 32);
    CHECK(report.report_id_ma().size() == 32);
    CHECK(report.reported_tcb().size() == 8);
    CHECK(report.chip_id().size() == 64);
    CHECK(report.committed_tcb().size() == 8);
    CHECK(report.launch_tcb().size() == 8);
    CHECK(report.signature_r().size() == 72);
    CHECK(report.signature_s().size() == 72);
}

TEST_CASE("snp.hpp: from_unverified decodes fields without authenticating them") {
    MilanInputs in = load_milan_inputs();
    in.report.at(0x90) ^= 0xff;

    AttestationReport report = AttestationReport::from_unverified(in.report);

    REQUIRE_FALSE(report.empty());
    CHECK(hex(report.measurement()).rfind("a0", 0) == 0);
    CHECK(report.version() == 3);
}

TEST_CASE("snp.hpp: a tampered report fails verification") {
    MilanInputs in = load_milan_inputs();
    // Corrupt the measurement region so the AMD signature no longer matches.
    in.report.at(0x90) ^= 0xff;

    try {
        (void)verify_milan(in);
        FAIL("verification of a tampered report succeeded");
    } catch (const tav::snp::Error &error) {
        CHECK(error.code() == TAV_ERROR_SNP_SIGNATURE_VERIFICATION_ERROR);
        // The TAV message is preserved rather than replaced by a wrapper string.
        CHECK(std::string(error.what()).size() > 0);
        CHECK(std::string(error.what()).find("ignature") != std::string::npos);
    }
}

TEST_CASE("snp.hpp: certificates are taken in ARK, ASK, VCEK order") {
    MilanInputs in = load_milan_inputs();

    // Swapping the ARK and ASK arguments must be rejected, so a caller cannot
    // pass the chain in the wrong order and still verify.
    try {
        (void)AttestationReport::verify(in.report, in.ask, in.ark, in.vcek);
        FAIL("verification with swapped ARK and ASK succeeded");
    } catch (const tav::snp::Error &error) {
        CHECK(error.code() == TAV_ERROR_SNP_INVALID_ROOT_CERTIFICATE);
    }

    // The VCEK is not a valid ASK either.
    CHECK_THROWS_AS((void)AttestationReport::verify(in.report, in.ark, in.vcek, in.ask),
                    tav::snp::Error);
}

TEST_CASE("snp.hpp: malformed input throws with the TAV code and message") {
    MilanInputs in = load_milan_inputs();
    in.report.pop_back();

    try {
        (void)AttestationReport::from_unverified(in.report);
        FAIL("decoding a truncated report succeeded");
    } catch (const tav::snp::Error &error) {
        CHECK(error.code() == TAV_ERROR_INVALID_ARGUMENT);
        CHECK(std::string(error.what()) ==
              "Invalid attestation report: expected 1184 bytes, got 1183");
    }

    try {
        (void)verify_milan(in);
        FAIL("verifying a truncated report succeeded");
    } catch (const tav::snp::Error &error) {
        CHECK(error.code() == TAV_ERROR_INVALID_ARGUMENT);
        CHECK(std::string(error.what()) ==
              "Invalid attestation report: expected 1184 bytes, got 1183");
    }
}

TEST_CASE("snp.hpp: an empty span is rejected rather than passed to the ABI") {
    std::span<const uint8_t> nothing;
    REQUIRE(nothing.data() == nullptr);

    try {
        (void)AttestationReport::from_unverified(nothing);
        FAIL("decoding an empty span succeeded");
    } catch (const tav::snp::Error &error) {
        CHECK(error.code() == TAV_ERROR_INVALID_ARGUMENT);
        CHECK(std::string(error.what()) == "attestation report is empty");
    }
}

TEST_CASE("snp.hpp: a default-constructed report is empty and throws on access") {
    AttestationReport report;

    CHECK(report.empty());
    CHECK_THROWS_AS((void)report.native_handle(), tav::snp::Error);

    try {
        (void)report.version();
        FAIL("reading an empty report succeeded");
    } catch (const tav::snp::Error &error) {
        CHECK(error.code() == TAV_ERROR_IS_NULL);
        CHECK(std::string(error.what()) == "SNP attestation report is empty");
    }

    // Every accessor guards the handle, so none of them reaches the C ABI with
    // a null report.
    CHECK_THROWS_AS((void)report.version(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.guest_svn(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.policy(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.policy_abi_minor(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.policy_abi_major(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.policy_smt(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.policy_migrate_ma(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.policy_debug(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.policy_single_socket(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.policy_cxl_allow(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.policy_mem_aes_256_xts(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.policy_rapl_dis(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.policy_ciphertext_hiding_dram(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.policy_page_swap_disable(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.vmpl(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.signature_algo(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.platform_info(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.flags(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.flags_author_key_en(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.flags_mask_chip_key(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.flags_signing_key(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.cpuid_fam_id(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.cpuid_mod_id(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.cpuid_step(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.current_build(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.current_minor(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.current_major(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.committed_build(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.committed_minor(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.committed_major(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.report_data(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.family_id(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.image_id(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.platform_version(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.measurement(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.host_data(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.id_key_digest(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.author_key_digest(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.report_id(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.report_id_ma(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.reported_tcb(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.chip_id(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.committed_tcb(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.launch_tcb(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.signature_r(), tav::snp::Error);
    CHECK_THROWS_AS((void)report.signature_s(), tav::snp::Error);
}

TEST_CASE("snp.hpp: a failed factory leaves the target empty") {
    MilanInputs in = load_milan_inputs();
    std::vector<uint8_t> truncated(in.report.begin(), in.report.end() - 1);

    AttestationReport report = AttestationReport::from_unverified(in.report);
    REQUIRE_FALSE(report.empty());

    // The failing factory throws, so the caller keeps the report it had.
    CHECK_THROWS_AS(report = AttestationReport::from_unverified(truncated),
                    tav::snp::Error);
    CHECK_FALSE(report.empty());
    CHECK(report.version() == 3);
}

TEST_CASE("snp.hpp: borrowed views come from the report, not from the input") {
    MilanInputs in = load_milan_inputs();
    auto owned = std::make_unique<std::vector<uint8_t>>(in.report);

    AttestationReport report = AttestationReport::from_unverified(*owned);
    std::span<const uint8_t> measurement = report.measurement();

    // The view is not a window onto the caller's buffer.
    const size_t input_size = owned->size();
    const uintptr_t input_begin = reinterpret_cast<uintptr_t>(owned->data());
    const uintptr_t view = reinterpret_cast<uintptr_t>(measurement.data());
    CHECK((view < input_begin || view >= input_begin + input_size));

    // Repeated reads borrow the same report-owned storage.
    CHECK(report.measurement().data() == measurement.data());
    CHECK(report.chip_id().data() != measurement.data());

    // Freeing the input and letting the allocator reuse its storage leaves the
    // view intact.
    owned.reset();
    std::vector<uint8_t> scratch(input_size, 0xcd);
    CHECK(scratch.front() == 0xcd);
    CHECK(hex(report.measurement()) ==
          "5feee30d6d7e1a29f403d70a4198237ddfb13051a2d6976439487c609388ed7f9818"
          "9887920ab2fa0096903a0c23fca1");
    CHECK(measurement.data() == report.measurement().data());
}

TEST_CASE("snp.hpp: moves transfer the handle and keep views valid") {
    MilanInputs in = load_milan_inputs();
    AttestationReport source = verify_milan(in);

    const TavSnpAttestationReport *handle = source.native_handle();
    const uint8_t *measurement = source.measurement().data();

    AttestationReport moved(std::move(source));

    CHECK(source.empty()); // NOLINT(bugprone-use-after-move)
    CHECK_THROWS_AS((void)source.native_handle(), tav::snp::Error);
    REQUIRE_FALSE(moved.empty());
    CHECK(moved.native_handle() == handle);
    CHECK(moved.measurement().data() == measurement);
    CHECK(moved.version() == 3);

    AttestationReport target;
    target = std::move(moved);

    CHECK(moved.empty()); // NOLINT(bugprone-use-after-move)
    CHECK(target.native_handle() == handle);
    CHECK(target.measurement().data() == measurement);

    // Move assignment onto a live report releases the handle it held; running
    // this test under a leak checker is what proves it.
    AttestationReport replaced = AttestationReport::from_unverified(in.report);
    REQUIRE(replaced.native_handle() != handle);
    replaced = std::move(target);
    CHECK(replaced.native_handle() == handle);
    CHECK(target.empty()); // NOLINT(bugprone-use-after-move)
}

TEST_CASE("snp.hpp: self-move leaves the report usable") {
    MilanInputs in = load_milan_inputs();
    AttestationReport report = AttestationReport::from_unverified(in.report);
    const TavSnpAttestationReport *handle = report.native_handle();

    // The alias keeps this a self-move without tripping -Wself-move.
    AttestationReport &alias = report;
    report = std::move(alias);

    REQUIRE_FALSE(report.empty());
    CHECK(report.native_handle() == handle);
    CHECK(report.version() == 3);
}

TEST_CASE("snp.hpp: native_handle drives the C ABI directly") {
    MilanInputs in = load_milan_inputs();
    AttestationReport report = verify_milan(in);

    const TavSnpAttestationReport *handle = report.native_handle();
    REQUIRE(handle != nullptr);

    CHECK(tav_snp_attestation_report_version(handle) == report.version());
    CHECK(tav_snp_attestation_report_policy(handle) == report.policy());

    const uint8_t *data = nullptr;
    size_t len = 0;
    tav_snp_attestation_report_chip_id(handle, &data, &len);
    CHECK(data == report.chip_id().data());
    CHECK(len == report.chip_id().size());
}

namespace {

// The public C accessor prefix the wrapper method names drop.
constexpr const char kAccessorPrefix[] = "tav_snp_attestation_report_";

// Wrapper methods that are not C accessors, so they take part in neither
// direction of the parity check below.
bool is_wrapper_only(const std::string &name) {
    return name == "native_handle" || name == "checked";
}

std::string trimmed(const std::string &text) {
    size_t begin = text.find_first_not_of(" \t");
    if (begin == std::string::npos) return "";
    size_t end = text.find_last_not_of(" \t");
    return text.substr(begin, end - begin + 1);
}

std::vector<std::string> lines_of(const std::string &text) {
    std::vector<std::string> lines;
    size_t begin = 0;
    while (begin <= text.size()) {
        size_t end = text.find('\n', begin);
        if (end == std::string::npos) end = text.size();
        lines.push_back(text.substr(begin, end - begin));
        begin = end + 1;
    }
    return lines;
}

// Maps each report accessor declared in tav/snp.h to the return type the
// wrapper must expose for it. A C byte accessor writes its borrowed view
// through out-parameters, which the wrapper returns as a span.
std::map<std::string, std::string> c_accessors(const std::string &header) {
    std::map<std::string, std::string> accessors;
    for (const std::string &raw : lines_of(header)) {
        std::string line = trimmed(raw);
        if (line.rfind("TAV_API ", 0) != 0) continue;

        size_t paren = line.find('(');
        if (paren == std::string::npos) continue;
        size_t name_begin = line.find_last_of(" *", paren - 1) + 1;
        std::string name = line.substr(name_begin, paren - name_begin);
        if (name.rfind(kAccessorPrefix, 0) != 0) continue;

        std::string suffix = name.substr(sizeof(kAccessorPrefix) - 1);
        if (suffix == "free" || suffix == "from_unverified_bytes") continue;

        std::string return_type =
            trimmed(line.substr(sizeof("TAV_API ") - 1, name_begin - sizeof("TAV_API ")));
        if (return_type == "void") return_type = "std::span<const uint8_t>";

        REQUIRE_MESSAGE(accessors.emplace(suffix, return_type).second,
                        "duplicate C accessor: " << suffix);
    }
    return accessors;
}

// Maps each nodiscard `type name() const` method declared in tav/snp.hpp to
// its return type. Methods with a trailing specifier or any parameter are not
// accessors and are skipped.
std::map<std::string, std::string> cpp_accessors(const std::string &header) {
    std::map<std::string, std::string> accessors;
    const std::string marker = "[[nodiscard]] ";
    const std::string tail = "() const";
    for (const std::string &raw : lines_of(header)) {
        std::string line = trimmed(raw);
        if (line.rfind(marker, 0) != 0) continue;
        if (line.size() < tail.size() ||
            line.compare(line.size() - tail.size(), tail.size(), tail) != 0) {
            continue;
        }

        std::string declaration =
            line.substr(marker.size(), line.size() - marker.size() - tail.size());
        size_t name_begin = declaration.find_last_of(" *") + 1;
        std::string name = declaration.substr(name_begin);
        if (is_wrapper_only(name)) continue;

        std::string return_type = trimmed(declaration.substr(0, name_begin));
        REQUIRE_MESSAGE(accessors.emplace(name, return_type).second,
                        "duplicate wrapper method: " << name);
    }
    return accessors;
}

} // namespace

TEST_CASE("snp.hpp: every C accessor has a wrapper method of the same type") {
    std::map<std::string, std::string> c_side =
        c_accessors(to_string(read_file("ffi/include/tav/snp.h")));
    std::map<std::string, std::string> cpp_side =
        cpp_accessors(to_string(read_file("ffi/include/tav/snp.hpp")));

    // Guards against a parse that silently matched nothing.
    CHECK(c_side.size() == 46);
    CHECK(cpp_side.size() == 46);

    for (const auto &[suffix, return_type] : c_side) {
        auto found = cpp_side.find(suffix);
        REQUIRE_MESSAGE(found != cpp_side.end(),
                        "tav/snp.hpp is missing a method for " << suffix);
        CHECK_MESSAGE(found->second == return_type,
                      "wrong return type for " << suffix << ": expected "
                                               << return_type << ", found "
                                               << found->second);
    }

    for (const auto &[name, return_type] : cpp_side) {
        (void)return_type;
        CHECK_MESSAGE(c_side.count(name) == 1,
                      "tav/snp.hpp exposes " << name
                                             << ", which tav/snp.h does not declare");
    }
}
