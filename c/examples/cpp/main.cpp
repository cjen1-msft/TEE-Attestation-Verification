// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Example: verify an SEV-SNP attestation report from C++ using the
// tee-attestation-verification Rust library via its C FFI.
//
// Usage:
//   ./verify_example <report.bin> <ark.pem> <ask.pem> <vcek.pem>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "tee_attestation_verification.h"

struct TAVErrorDeleter {
    void operator()(TAVError *err) const {
        tav_free_error(err);
    }
};

struct TAVReportDeleter {
    void operator()(TAVSNPAttestationReport *report) const {
        tav_free_report(report);
    }
};

using TAVErrorPtr = std::unique_ptr<TAVError, TAVErrorDeleter>;
using TAVReportPtr = std::unique_ptr<TAVSNPAttestationReport, TAVReportDeleter>;

struct FileReadResult {
    std::vector<uint8_t> bytes;
    std::string error;
};

static FileReadResult read_file(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        return {{}, "cannot open " + path};
    }

    auto size = ifs.tellg();
    if (size < 0) {
        return {{}, "cannot determine size of " + path};
    }

    ifs.seekg(0);
    if (!ifs) {
        return {{}, "cannot seek " + path};
    }

    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    if (!bytes.empty()) {
        ifs.read(reinterpret_cast<char *>(bytes.data()), size);
        if (!ifs) {
            return {{}, "cannot read " + path};
        }
    }

    return {std::move(bytes), ""};
}

/// Print the first N bytes of a buffer as hex.
static void print_hex(const uint8_t *data, size_t len) {
    std::ios_base::fmtflags flags = std::cout.flags();
    char fill = std::cout.fill();

    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::setw(2) << static_cast<unsigned>(data[i]);
    }

    std::cout.flags(flags);
    std::cout.fill(fill);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        std::cerr << "usage: " << argv[0]
                  << " <report.bin> <ark.pem> <ask.pem> <vcek.pem>\n";
        return 1;
    }

    auto report_bytes_result = read_file(argv[1]);
    if (!report_bytes_result.error.empty()) {
        std::cerr << "error: " << report_bytes_result.error << "\n";
        return 1;
    }

    auto ark_result = read_file(argv[2]);
    if (!ark_result.error.empty()) {
        std::cerr << "error: " << ark_result.error << "\n";
        return 1;
    }

    auto ask_result = read_file(argv[3]);
    if (!ask_result.error.empty()) {
        std::cerr << "error: " << ask_result.error << "\n";
        return 1;
    }

    auto vcek_result = read_file(argv[4]);
    if (!vcek_result.error.empty()) {
        std::cerr << "error: " << vcek_result.error << "\n";
        return 1;
    }

    std::vector<uint8_t> report_bytes = std::move(report_bytes_result.bytes);
    std::vector<uint8_t> ark = std::move(ark_result.bytes);
    std::vector<uint8_t> ask = std::move(ask_result.bytes);
    std::vector<uint8_t> vcek = std::move(vcek_result.bytes);

    TAVError *raw_err = nullptr;
    TAVSNPAttestationReport *raw_report = tav_snp_verify_attestation(
        report_bytes.data(), report_bytes.size(),
        ark.data(),  ark.size(),
        ask.data(),  ask.size(),
        vcek.data(), vcek.size(),
        &raw_err
    );
    TAVErrorPtr err(raw_err);

    if (raw_report == nullptr) {
        std::cerr << "verification failed (code "
                  << static_cast<unsigned>(tav_error_code(err.get())) << "): "
                  << tav_error_message(err.get()) << "\n";
        return 1;
    }

    TAVReportPtr report(raw_report);

    std::cout << "verification succeeded\n\n";

    std::cout << "  version:           " << tav_snp_report_version(report.get())       << "\n"
              << "  guest_svn:         " << tav_snp_report_guest_svn(report.get())     << "\n"
              << "  policy:            0x" << std::hex << tav_snp_report_policy(report.get()) << std::dec << "\n"
              << "    abi_minor:       " << static_cast<unsigned>(tav_snp_report_policy_abi_minor(report.get())) << "\n"
              << "    abi_major:       " << static_cast<unsigned>(tav_snp_report_policy_abi_major(report.get())) << "\n"
              << "    smt:             " << static_cast<unsigned>(tav_snp_report_policy_smt(report.get())) << "\n"
              << "    migrate_ma:      " << static_cast<unsigned>(tav_snp_report_policy_migrate_ma(report.get())) << "\n"
              << "    debug:           " << static_cast<unsigned>(tav_snp_report_policy_debug(report.get())) << "\n"
              << "    single_socket:   " << static_cast<unsigned>(tav_snp_report_policy_single_socket(report.get())) << "\n"
              << "    cxl_allow:       " << static_cast<unsigned>(tav_snp_report_policy_cxl_allow(report.get())) << "\n"
              << "    mem_aes_256_xts: " << static_cast<unsigned>(tav_snp_report_policy_mem_aes_256_xts(report.get())) << "\n"
              << "    rapl_dis:        " << static_cast<unsigned>(tav_snp_report_policy_rapl_dis(report.get())) << "\n"
              << "    ciphertext_hiding_dram: " << static_cast<unsigned>(tav_snp_report_policy_ciphertext_hiding_dram(report.get())) << "\n"
              << "    page_swap_disable: " << static_cast<unsigned>(tav_snp_report_policy_page_swap_disable(report.get())) << "\n"
              << "  family_id:         "; print_hex(tav_snp_report_family_id(report.get()), TAV_SNP_FAMILY_ID_SIZE);
    std::cout << "\n"
              << "  image_id:          "; print_hex(tav_snp_report_image_id(report.get()), TAV_SNP_IMAGE_ID_SIZE);
    std::cout << "\n"
              << "  vmpl:              " << tav_snp_report_vmpl(report.get())          << "\n"
              << "  signature_algo:    " << tav_snp_report_signature_algo(report.get()) << "\n"
              << "  platform_version:  "; print_hex(tav_snp_report_platform_version(report.get()), TAV_SNP_TCB_VERSION_SIZE);
    std::cout << "\n"
              << "  platform_info:     0x" << std::hex << tav_snp_report_platform_info(report.get()) << std::dec << "\n"
              << "  flags:             0x" << std::hex << tav_snp_report_flags(report.get()) << std::dec << "\n"
              << "    author_key_en:   " << static_cast<unsigned>(tav_snp_report_flags_author_key_en(report.get())) << "\n"
              << "    mask_chip_key:   " << static_cast<unsigned>(tav_snp_report_flags_mask_chip_key(report.get())) << "\n"
              << "    signing_key:     " << static_cast<unsigned>(tav_snp_report_flags_signing_key(report.get())) << "\n"
              << "  report_data:       "; print_hex(tav_snp_report_report_data(report.get()), TAV_SNP_REPORT_DATA_SIZE);
    std::cout << "\n"
              << "  measurement:       "; print_hex(tav_snp_report_measurement(report.get()), TAV_SNP_MEASUREMENT_SIZE);
    std::cout << "\n"
              << "  host_data:         "; print_hex(tav_snp_report_host_data(report.get()), TAV_SNP_HOST_DATA_SIZE);
    std::cout << "\n"
              << "  id_key_digest:     "; print_hex(tav_snp_report_id_key_digest(report.get()), TAV_SNP_ID_KEY_DIGEST_SIZE);
    std::cout << "\n"
              << "  author_key_digest: "; print_hex(tav_snp_report_author_key_digest(report.get()), TAV_SNP_AUTHOR_KEY_DIGEST_SIZE);
    std::cout << "\n"
              << "  report_id:         "; print_hex(tav_snp_report_report_id(report.get()), TAV_SNP_REPORT_ID_SIZE);
    std::cout << "\n"
              << "  report_id_ma:      "; print_hex(tav_snp_report_report_id_ma(report.get()), TAV_SNP_REPORT_ID_MA_SIZE);
    std::cout << "\n"
              << "  reported_tcb:      "; print_hex(tav_snp_report_reported_tcb(report.get()), TAV_SNP_TCB_VERSION_SIZE);
    std::cout << "\n"
              << "  cpuid_fam_id:      " << static_cast<unsigned>(tav_snp_report_cpuid_fam_id(report.get())) << "\n"
              << "  cpuid_mod_id:      " << static_cast<unsigned>(tav_snp_report_cpuid_mod_id(report.get())) << "\n"
              << "  cpuid_step:        " << static_cast<unsigned>(tav_snp_report_cpuid_step(report.get()))    << "\n"
              << "  chip_id:           "; print_hex(tav_snp_report_chip_id(report.get()), TAV_SNP_CHIP_ID_SIZE);
    std::cout << "\n"
              << "  committed_tcb:     "; print_hex(tav_snp_report_committed_tcb(report.get()), TAV_SNP_TCB_VERSION_SIZE);
    std::cout << "\n"
              << "  current_build:     " << static_cast<unsigned>(tav_snp_report_current_build(report.get())) << "\n"
              << "  current_minor:     " << static_cast<unsigned>(tav_snp_report_current_minor(report.get())) << "\n"
              << "  current_major:     " << static_cast<unsigned>(tav_snp_report_current_major(report.get())) << "\n"
              << "  committed_build:   " << static_cast<unsigned>(tav_snp_report_committed_build(report.get())) << "\n"
              << "  committed_minor:   " << static_cast<unsigned>(tav_snp_report_committed_minor(report.get())) << "\n"
              << "  committed_major:   " << static_cast<unsigned>(tav_snp_report_committed_major(report.get())) << "\n"
              << "  launch_tcb:        "; print_hex(tav_snp_report_launch_tcb(report.get()), TAV_SNP_TCB_VERSION_SIZE);
    std::cout << "\n"
              << "  signature.r:       "; print_hex(tav_snp_report_signature_r(report.get()), TAV_SNP_SIGNATURE_COMPONENT_SIZE);
    std::cout << "\n"
              << "  signature.s:       "; print_hex(tav_snp_report_signature_s(report.get()), TAV_SNP_SIGNATURE_COMPONENT_SIZE);
    std::cout << "\n";

    return 0;
}
