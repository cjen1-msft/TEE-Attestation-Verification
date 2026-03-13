/* Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 *
 * Pure C header for TEE Attestation Verification library.
 *
 * Link against the static library (libtee_attestation_verification_lib.a)
 * and system dependencies: -lpthread -ldl -lm
 */

#ifndef TEE_ATTESTATION_VERIFICATION_H
#define TEE_ATTESTATION_VERIFICATION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------- */
/* Error handling                                                          */
/* ----------------------------------------------------------------------- */

/** Error code categories.  Must stay in sync with Rust TAVErrorCode enum.
 *  Numbering convention:
 *    1:       FFI/input parsing failures (bad report, bad PEM, etc.)
 *    2:       Invalid/null error handle passed to error accessor
 *    101-105: attestation verification failures
 */
typedef uint32_t TAVErrorCode;

enum {
    TAV_ERROR_INVALID_ARGUMENT               = 1,
    TAV_ERROR_ERROR_CODE_IS_NULL             = 2,
    TAV_ERROR_UNSUPPORTED_PROCESSOR          = 101,
    TAV_ERROR_INVALID_ROOT_CERTIFICATE       = 102,
    TAV_ERROR_CERTIFICATE_CHAIN              = 103,
    TAV_ERROR_SIGNATURE_VERIFICATION         = 104,
    TAV_ERROR_TCB_VERIFICATION               = 105
};

/** Opaque error handle.
 *  Must be freed with tav_free_error() when non-null.
 */
struct TAVError;

/** Get the error category code from an error handle. */
TAVErrorCode tav_error_code(const struct TAVError *err);

/** Get a NUL-terminated error message from an error handle.
 *  The returned string is valid until tav_free_error() is called.
 *  Do NOT free the returned pointer. */
const char *tav_error_message(const struct TAVError *err);

/** Free an error returned by tav_snp_verify_attestation().
 *  Safe to call with NULL (no-op). */
void tav_free_error(struct TAVError *err);


/* ----------------------------------------------------------------------- */
/* Opaque report handle                                                    */
/* ----------------------------------------------------------------------- */

/** Opaque handle to a verified SNP attestation report.
 *  Returned by tav_snp_verify_attestation().  Must be freed with
 *  tav_free_report(). */
struct TAVSNPAttestationReport;

/* Field sizes for byte-array accessors. */
#define TAV_SNP_FAMILY_ID_SIZE          16
#define TAV_SNP_IMAGE_ID_SIZE           16
#define TAV_SNP_TCB_VERSION_SIZE        8
#define TAV_SNP_REPORT_DATA_SIZE        64
#define TAV_SNP_MEASUREMENT_SIZE        48
#define TAV_SNP_HOST_DATA_SIZE          32
#define TAV_SNP_ID_KEY_DIGEST_SIZE      48
#define TAV_SNP_AUTHOR_KEY_DIGEST_SIZE  48
#define TAV_SNP_REPORT_ID_SIZE          32
#define TAV_SNP_REPORT_ID_MA_SIZE       32
#define TAV_SNP_CHIP_ID_SIZE            64
#define TAV_SNP_SIGNATURE_COMPONENT_SIZE 72

/* Signing-key selector values returned by tav_snp_report_flags_signing_key(). */
typedef uint8_t TAVSNPReportSigningKey;

enum {
    TAV_SNP_REPORT_SIGNING_KEY_VCEK = 0,
    TAV_SNP_REPORT_SIGNING_KEY_VLEK = 1,
    TAV_SNP_REPORT_SIGNING_KEY_NONE = 7
};

/* ----------------------------------------------------------------------- */
/* FFI verify functions                                                    */
/* ----------------------------------------------------------------------- */

/**
 * Verify an SEV-SNP attestation report using caller-provided ARK, ASK,
 * and VCEK certificates (all PEM-encoded).
 *
 * @param report_ptr    Pointer to the raw attestation report (1184 bytes).
 * @param report_len    Length of the report buffer in bytes.
 * @param ark_pem_ptr   Pointer to the PEM-encoded ARK certificate.
 * @param ark_pem_len   Length of the ARK PEM buffer in bytes.
 * @param ask_pem_ptr   Pointer to the PEM-encoded ASK certificate.
 * @param ask_pem_len   Length of the ASK PEM buffer in bytes.
 * @param vcek_pem_ptr  Pointer to the PEM-encoded VCEK certificate.
 * @param vcek_pem_len  Length of the VCEK PEM buffer in bytes.
 * @param err_out       Optional error output. If non-NULL, `*err_out` must be
 *                      NULL on entry; it is set to NULL on success and set to
 *                      an opaque error handle on failure. Any returned error
 *                      handle must be freed with tav_free_error().
 *
 * @return On success, an opaque report handle that must be freed with
 *         tav_free_report(). The returned handle borrows the attestation
 *         report bytes from report_ptr, so the caller must keep report_ptr
 *         alive and unchanged while using the handle. Use tav_snp_report_*()
 *         accessors to read fields.
 *         On failure, returns NULL and, if err_out is non-NULL, sets *err_out.
 */
struct TAVSNPAttestationReport *tav_snp_verify_attestation(
    const uint8_t        *report_ptr,
    size_t                report_len,
    const uint8_t        *ark_pem_ptr,
    size_t                ark_pem_len,
    const uint8_t        *ask_pem_ptr,
    size_t                ask_pem_len,
    const uint8_t        *vcek_pem_ptr,
    size_t                vcek_pem_len,
    struct TAVError     **err_out
);

/** Free a report returned by tav_snp_verify_attestation().
 *  Safe to call with NULL (no-op). */
void tav_free_report(struct TAVSNPAttestationReport *report);

/* ----------------------------------------------------------------------- */
/* Report accessors – scalar fields (native byte order)                    */
/* ----------------------------------------------------------------------- */
/* All report accessors require `report` to be a non-NULL pointer returned  */
/* by tav_snp_verify_attestation(). Because the report handle borrows from   */
/* report_ptr, the original report buffer must remain alive and unchanged    */
/* until tav_free_report() is called.                                        */

uint32_t tav_snp_report_version(const struct TAVSNPAttestationReport *report);
uint32_t tav_snp_report_guest_svn(const struct TAVSNPAttestationReport *report);
uint64_t tav_snp_report_policy(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_policy_abi_minor(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_policy_abi_major(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_policy_smt(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_policy_migrate_ma(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_policy_debug(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_policy_single_socket(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_policy_cxl_allow(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_policy_mem_aes_256_xts(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_policy_rapl_dis(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_policy_ciphertext_hiding_dram(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_policy_page_swap_disable(const struct TAVSNPAttestationReport *report);
uint32_t tav_snp_report_vmpl(const struct TAVSNPAttestationReport *report);
uint32_t tav_snp_report_signature_algo(const struct TAVSNPAttestationReport *report);
uint64_t tav_snp_report_platform_info(const struct TAVSNPAttestationReport *report);
uint32_t tav_snp_report_flags(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_flags_author_key_en(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_flags_mask_chip_key(const struct TAVSNPAttestationReport *report);
TAVSNPReportSigningKey tav_snp_report_flags_signing_key(const struct TAVSNPAttestationReport *report);

/* ----------------------------------------------------------------------- */
/* Report accessors – single-byte fields                                   */
/* ----------------------------------------------------------------------- */

uint8_t tav_snp_report_cpuid_fam_id(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_cpuid_mod_id(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_cpuid_step(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_current_build(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_current_minor(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_current_major(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_committed_build(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_committed_minor(const struct TAVSNPAttestationReport *report);
uint8_t tav_snp_report_committed_major(const struct TAVSNPAttestationReport *report);

/* ----------------------------------------------------------------------- */
/* Report accessors – byte-array fields                                    */
/* ----------------------------------------------------------------------- */
/* Returned pointers borrow from the report handle and are valid until      */
/* tav_free_report() is called.  See TAV_SNP_*_SIZE defines for lengths.    */

const uint8_t *tav_snp_report_family_id(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_image_id(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_platform_version(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_report_data(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_measurement(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_host_data(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_id_key_digest(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_author_key_digest(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_report_id(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_report_id_ma(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_reported_tcb(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_chip_id(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_committed_tcb(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_launch_tcb(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_signature_r(const struct TAVSNPAttestationReport *report);
const uint8_t *tav_snp_report_signature_s(const struct TAVSNPAttestationReport *report);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TEE_ATTESTATION_VERIFICATION_H */
