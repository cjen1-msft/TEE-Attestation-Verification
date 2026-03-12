// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Example: verify an SEV-SNP attestation report from C++ using the
// tee-attestation-verification Rust library via its C FFI.
//
// Usage:
//   ./verify_example <report.bin> <ark.pem> <ask.pem> <vcek.pem>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "tee_attestation_verification.h"

/// Read an entire file into a byte vector.
static std::vector<uint8_t> read_file(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        std::cerr << "error: cannot open " << path << "\n";
        std::exit(1);
    }
    auto size = ifs.tellg();
    ifs.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    ifs.read(reinterpret_cast<char *>(buf.data()), size);
    return buf;
}

/// Print the first N bytes of a buffer as hex.
static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        std::printf("%02x", data[i]);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        std::cerr << "usage: " << argv[0]
                  << " <report.bin> <ark.pem> <ask.pem> <vcek.pem>\n";
        return 1;
    }

    auto report_bytes = read_file(argv[1]);
    auto ark  = read_file(argv[2]);
    auto ask  = read_file(argv[3]);
    auto vcek = read_file(argv[4]);

    TAVError *err = nullptr;
    TAVSNPAttestationReport *report = tav_snp_verify_attestation(
        report_bytes.data(), report_bytes.size(),
        ark.data(),  ark.size(),
        ask.data(),  ask.size(),
        vcek.data(), vcek.size(),
        &err
    );

    if (report == nullptr) {
        std::cerr << "verification failed (code "
                  << static_cast<unsigned>(tav_error_code(err)) << "): "
                  << tav_error_message(err) << "\n";
        tav_free_error(err);
        return 1;
    }

    std::cout << "verification succeeded\n\n";

    std::cout << "  version:           " << tav_snp_report_version(report)       << "\n"
              << "  guest_svn:         " << tav_snp_report_guest_svn(report)     << "\n"
              << "  policy:            0x" << std::hex << tav_snp_report_policy(report) << std::dec << "\n"
              << "  family_id:         "; print_hex(tav_snp_report_family_id(report), TAV_SNP_FAMILY_ID_SIZE);
    std::cout << "\n"
              << "  image_id:          "; print_hex(tav_snp_report_image_id(report), TAV_SNP_IMAGE_ID_SIZE);
    std::cout << "\n"
              << "  vmpl:              " << tav_snp_report_vmpl(report)          << "\n"
              << "  signature_algo:    " << tav_snp_report_signature_algo(report) << "\n"
              << "  platform_version:  "; print_hex(tav_snp_report_platform_version(report), TAV_SNP_TCB_VERSION_SIZE);
    std::cout << "\n"
              << "  platform_info:     0x" << std::hex << tav_snp_report_platform_info(report) << std::dec << "\n"
              << "  flags:             0x" << std::hex << tav_snp_report_flags(report) << std::dec << "\n"
              << "  report_data:       "; print_hex(tav_snp_report_report_data(report), TAV_SNP_REPORT_DATA_SIZE);
    std::cout << "\n"
              << "  measurement:       "; print_hex(tav_snp_report_measurement(report), TAV_SNP_MEASUREMENT_SIZE);
    std::cout << "\n"
              << "  host_data:         "; print_hex(tav_snp_report_host_data(report), TAV_SNP_HOST_DATA_SIZE);
    std::cout << "\n"
              << "  id_key_digest:     "; print_hex(tav_snp_report_id_key_digest(report), TAV_SNP_ID_KEY_DIGEST_SIZE);
    std::cout << "\n"
              << "  author_key_digest: "; print_hex(tav_snp_report_author_key_digest(report), TAV_SNP_AUTHOR_KEY_DIGEST_SIZE);
    std::cout << "\n"
              << "  report_id:         "; print_hex(tav_snp_report_report_id(report), TAV_SNP_REPORT_ID_SIZE);
    std::cout << "\n"
              << "  report_id_ma:      "; print_hex(tav_snp_report_report_id_ma(report), TAV_SNP_REPORT_ID_MA_SIZE);
    std::cout << "\n"
              << "  reported_tcb:      "; print_hex(tav_snp_report_reported_tcb(report), TAV_SNP_TCB_VERSION_SIZE);
    std::cout << "\n"
              << "  cpuid_fam_id:      " << static_cast<unsigned>(tav_snp_report_cpuid_fam_id(report)) << "\n"
              << "  cpuid_mod_id:      " << static_cast<unsigned>(tav_snp_report_cpuid_mod_id(report)) << "\n"
              << "  cpuid_step:        " << static_cast<unsigned>(tav_snp_report_cpuid_step(report))    << "\n"
              << "  chip_id:           "; print_hex(tav_snp_report_chip_id(report), TAV_SNP_CHIP_ID_SIZE);
    std::cout << "\n"
              << "  committed_tcb:     "; print_hex(tav_snp_report_committed_tcb(report), TAV_SNP_TCB_VERSION_SIZE);
    std::cout << "\n"
              << "  current_build:     " << static_cast<unsigned>(tav_snp_report_current_build(report)) << "\n"
              << "  current_minor:     " << static_cast<unsigned>(tav_snp_report_current_minor(report)) << "\n"
              << "  current_major:     " << static_cast<unsigned>(tav_snp_report_current_major(report)) << "\n"
              << "  committed_build:   " << static_cast<unsigned>(tav_snp_report_committed_build(report)) << "\n"
              << "  committed_minor:   " << static_cast<unsigned>(tav_snp_report_committed_minor(report)) << "\n"
              << "  committed_major:   " << static_cast<unsigned>(tav_snp_report_committed_major(report)) << "\n"
              << "  launch_tcb:        "; print_hex(tav_snp_report_launch_tcb(report), TAV_SNP_TCB_VERSION_SIZE);
    std::cout << "\n"
              << "  signature.r:       "; print_hex(tav_snp_report_signature_r(report), TAV_SNP_SIGNATURE_COMPONENT_SIZE);
    std::cout << "\n"
              << "  signature.s:       "; print_hex(tav_snp_report_signature_s(report), TAV_SNP_SIGNATURE_COMPONENT_SIZE);
    std::cout << "\n";

    tav_free_report(report);

    return 0;
}
