// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

// RAII wrapper over the SNP attestation C ABI in <tav/snp.h>. This is the
// supported C++ interface; the C ABI beneath it stays available for callers
// that need it.
//
// Handle ownership:
// - An AttestationReport owns one report handle and frees it on destruction.
//   Reports cannot be copied, so one handle is never freed twice. Moving
//   transfers the handle and leaves the source empty(). Move assignment frees
//   the handle the target held.
// - A default-constructed or moved-from report is empty(). Every accessor on
//   an empty report throws Error rather than calling the C ABI, which does not
//   accept a null handle.
//
// Payload ownership:
// - Scalars are copied. Byte accessors return spans borrowed from the report,
//   not from the buffer a factory was called with, so a factory input can be
//   freed or reused once the report exists. A span stays valid while the
//   report that produced it owns its handle: it survives moves of that report,
//   and is invalidated when the owning handle is freed by destruction or by
//   move assignment onto the owner.
//
// Failures throw Error, which carries the TavErrorCode and the message of the
// underlying TavError.

#include <tav/snp.h>
#include <tav/utils.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

namespace tav::snp
{
/// Failure of a report factory or of an access to an empty report.
class Error : public std::runtime_error
{
public:
    Error(TavErrorCode code, const std::string& what) :
      std::runtime_error(what),
      code_(code)
    {}

    [[nodiscard]] TavErrorCode code() const noexcept
    {
        return code_;
    }

private:
    TavErrorCode code_;
};

/// An owning SNP attestation report. Moving transfers the handle and empties
/// the source.
class AttestationReport
{
public:
    /// Constructs an empty report, which owns no handle.
    AttestationReport() = default;

    AttestationReport(const AttestationReport&) = delete;
    AttestationReport& operator=(const AttestationReport&) = delete;

    AttestationReport(AttestationReport&& other) noexcept :
      handle_(std::exchange(other.handle_, nullptr))
    {}

    AttestationReport& operator=(AttestationReport&& other) noexcept
    {
        if (this != &other)
        {
            tav_snp_attestation_report_free(handle_);
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    ~AttestationReport()
    {
        tav_snp_attestation_report_free(handle_);
    }

    /// Decodes a report without cryptographic verification.
    ///
    /// Only the fixed report size is checked. Field values, reserved bytes,
    /// signatures, certificates and TCBs are not validated, so do not make
    /// trust decisions from the result.
    [[nodiscard]] static AttestationReport from_unverified(
      std::span<const uint8_t> report)
    {
        AttestationReport out;
        Failure failure(tav_snp_attestation_report_from_unverified_bytes(
          report.data(), report.size(), &out.handle_));
        failure.rethrow();
        return out;
    }

    /// Verifies a report against caller-provided ARK, ASK and VCEK
    /// certificates in PEM format, in the order the C ABI takes them.
    [[nodiscard]] static AttestationReport verify(
      std::span<const uint8_t> report,
      std::span<const uint8_t> ark_pem,
      std::span<const uint8_t> ask_pem,
      std::span<const uint8_t> vcek_pem)
    {
        AttestationReport out;
        Failure failure(tav_verify_snp_attestation(
          report.data(),
          report.size(),
          ark_pem.data(),
          ark_pem.size(),
          ask_pem.data(),
          ask_pem.size(),
          vcek_pem.data(),
          vcek_pem.size(),
          &out.handle_));
        failure.rethrow();
        return out;
    }

    /// True once the report has been moved out of, or if it was never
    /// constructed from bytes.
    [[nodiscard]] bool empty() const noexcept
    {
        return handle_ == nullptr;
    }

    /// Borrows the handle for C interop. The report keeps ownership, so do not
    /// free the returned handle. Throws if the report is empty.
    [[nodiscard]] const TavSnpAttestationReport* native_handle() const
    {
        return checked();
    }

    [[nodiscard]] uint32_t version() const
    {
        return tav_snp_attestation_report_version(checked());
    }

    [[nodiscard]] uint32_t guest_svn() const
    {
        return tav_snp_attestation_report_guest_svn(checked());
    }

    [[nodiscard]] uint64_t policy() const
    {
        return tav_snp_attestation_report_policy(checked());
    }

    [[nodiscard]] uint8_t policy_abi_minor() const
    {
        return tav_snp_attestation_report_policy_abi_minor(checked());
    }

    [[nodiscard]] uint8_t policy_abi_major() const
    {
        return tav_snp_attestation_report_policy_abi_major(checked());
    }

    [[nodiscard]] bool policy_smt() const
    {
        return tav_snp_attestation_report_policy_smt(checked());
    }

    [[nodiscard]] bool policy_migrate_ma() const
    {
        return tav_snp_attestation_report_policy_migrate_ma(checked());
    }

    [[nodiscard]] bool policy_debug() const
    {
        return tav_snp_attestation_report_policy_debug(checked());
    }

    [[nodiscard]] bool policy_single_socket() const
    {
        return tav_snp_attestation_report_policy_single_socket(checked());
    }

    [[nodiscard]] bool policy_cxl_allow() const
    {
        return tav_snp_attestation_report_policy_cxl_allow(checked());
    }

    [[nodiscard]] bool policy_mem_aes_256_xts() const
    {
        return tav_snp_attestation_report_policy_mem_aes_256_xts(checked());
    }

    [[nodiscard]] bool policy_rapl_dis() const
    {
        return tav_snp_attestation_report_policy_rapl_dis(checked());
    }

    [[nodiscard]] bool policy_ciphertext_hiding_dram() const
    {
        return tav_snp_attestation_report_policy_ciphertext_hiding_dram(checked());
    }

    [[nodiscard]] bool policy_page_swap_disable() const
    {
        return tav_snp_attestation_report_policy_page_swap_disable(checked());
    }

    [[nodiscard]] uint32_t vmpl() const
    {
        return tav_snp_attestation_report_vmpl(checked());
    }

    [[nodiscard]] uint32_t signature_algo() const
    {
        return tav_snp_attestation_report_signature_algo(checked());
    }

    [[nodiscard]] uint64_t platform_info() const
    {
        return tav_snp_attestation_report_platform_info(checked());
    }

    [[nodiscard]] uint32_t flags() const
    {
        return tav_snp_attestation_report_flags(checked());
    }

    [[nodiscard]] bool flags_author_key_en() const
    {
        return tav_snp_attestation_report_flags_author_key_en(checked());
    }

    [[nodiscard]] bool flags_mask_chip_key() const
    {
        return tav_snp_attestation_report_flags_mask_chip_key(checked());
    }

    [[nodiscard]] uint8_t flags_signing_key() const
    {
        return tav_snp_attestation_report_flags_signing_key(checked());
    }

    [[nodiscard]] uint8_t cpuid_fam_id() const
    {
        return tav_snp_attestation_report_cpuid_fam_id(checked());
    }

    [[nodiscard]] uint8_t cpuid_mod_id() const
    {
        return tav_snp_attestation_report_cpuid_mod_id(checked());
    }

    [[nodiscard]] uint8_t cpuid_step() const
    {
        return tav_snp_attestation_report_cpuid_step(checked());
    }

    [[nodiscard]] uint8_t current_build() const
    {
        return tav_snp_attestation_report_current_build(checked());
    }

    [[nodiscard]] uint8_t current_minor() const
    {
        return tav_snp_attestation_report_current_minor(checked());
    }

    [[nodiscard]] uint8_t current_major() const
    {
        return tav_snp_attestation_report_current_major(checked());
    }

    [[nodiscard]] uint8_t committed_build() const
    {
        return tav_snp_attestation_report_committed_build(checked());
    }

    [[nodiscard]] uint8_t committed_minor() const
    {
        return tav_snp_attestation_report_committed_minor(checked());
    }

    [[nodiscard]] uint8_t committed_major() const
    {
        return tav_snp_attestation_report_committed_major(checked());
    }

    /// Byte accessors below return views borrowed from this report. Each view
    /// is invalidated when this report frees its handle.

    [[nodiscard]] std::span<const uint8_t> report_data() const
    {
        return borrow(tav_snp_attestation_report_report_data);
    }

    [[nodiscard]] std::span<const uint8_t> family_id() const
    {
        return borrow(tav_snp_attestation_report_family_id);
    }

    [[nodiscard]] std::span<const uint8_t> image_id() const
    {
        return borrow(tav_snp_attestation_report_image_id);
    }

    /// Raw TCB version bytes, as they appear in the report.
    [[nodiscard]] std::span<const uint8_t> platform_version() const
    {
        return borrow(tav_snp_attestation_report_platform_version);
    }

    [[nodiscard]] std::span<const uint8_t> measurement() const
    {
        return borrow(tav_snp_attestation_report_measurement);
    }

    [[nodiscard]] std::span<const uint8_t> host_data() const
    {
        return borrow(tav_snp_attestation_report_host_data);
    }

    [[nodiscard]] std::span<const uint8_t> id_key_digest() const
    {
        return borrow(tav_snp_attestation_report_id_key_digest);
    }

    [[nodiscard]] std::span<const uint8_t> author_key_digest() const
    {
        return borrow(tav_snp_attestation_report_author_key_digest);
    }

    [[nodiscard]] std::span<const uint8_t> report_id() const
    {
        return borrow(tav_snp_attestation_report_report_id);
    }

    [[nodiscard]] std::span<const uint8_t> report_id_ma() const
    {
        return borrow(tav_snp_attestation_report_report_id_ma);
    }

    /// Raw TCB version bytes, as they appear in the report.
    [[nodiscard]] std::span<const uint8_t> reported_tcb() const
    {
        return borrow(tav_snp_attestation_report_reported_tcb);
    }

    [[nodiscard]] std::span<const uint8_t> chip_id() const
    {
        return borrow(tav_snp_attestation_report_chip_id);
    }

    /// Raw TCB version bytes, as they appear in the report.
    [[nodiscard]] std::span<const uint8_t> committed_tcb() const
    {
        return borrow(tav_snp_attestation_report_committed_tcb);
    }

    /// Raw TCB version bytes, as they appear in the report.
    [[nodiscard]] std::span<const uint8_t> launch_tcb() const
    {
        return borrow(tav_snp_attestation_report_launch_tcb);
    }

    [[nodiscard]] std::span<const uint8_t> signature_r() const
    {
        return borrow(tav_snp_attestation_report_signature_r);
    }

    [[nodiscard]] std::span<const uint8_t> signature_s() const
    {
        return borrow(tav_snp_attestation_report_signature_s);
    }

private:
    /// Owns the TavError a factory returned, so it is freed even if building
    /// the exception below throws.
    class Failure
    {
    public:
        explicit Failure(TavError* error) : error_(error) {}
        Failure(const Failure&) = delete;
        Failure& operator=(const Failure&) = delete;
        Failure(Failure&&) = delete;
        Failure& operator=(Failure&&) = delete;

        ~Failure()
        {
            tav_error_free(error_);
        }

        /// Throws Error if the factory failed, and does nothing otherwise.
        void rethrow() const
        {
            if (error_ != nullptr)
            {
                throw Error(tav_error_code(error_), tav_error_message(error_));
            }
        }

    private:
        TavError* error_;
    };

    using BytesAccessor =
      void (*)(const TavSnpAttestationReport*, const uint8_t**, size_t*);

    /// The handle the C ABI accessors need, which they may not receive as
    /// null.
    [[nodiscard]] const TavSnpAttestationReport* checked() const
    {
        if (handle_ == nullptr)
        {
            throw Error(TAV_ERROR_IS_NULL, "SNP attestation report is empty");
        }
        return handle_;
    }

    [[nodiscard]] std::span<const uint8_t> borrow(BytesAccessor accessor) const
    {
        const uint8_t* data = nullptr;
        size_t len = 0;
        accessor(checked(), &data, &len);
        return {data, len};
    }

    TavSnpAttestationReport* handle_{nullptr};
};
}
