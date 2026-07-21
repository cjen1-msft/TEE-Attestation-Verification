// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;

namespace TeeAttestationVerification;

internal static partial class NativeMethods
{
    private const string LibraryName = "tee_attestation_verification_ffi";

    [LibraryImport(LibraryName, EntryPoint = "tav_error_code")]
    internal static partial int ErrorCode(IntPtr error);

    [LibraryImport(LibraryName, EntryPoint = "tav_error_message")]
    internal static partial IntPtr ErrorMessage(IntPtr error);

    [LibraryImport(LibraryName, EntryPoint = "tav_error_free")]
    internal static partial void ErrorFree(IntPtr error);

    [LibraryImport(LibraryName, EntryPoint = "tav_byte_buffer_data")]
    internal static partial IntPtr ByteBufferData(IntPtr buffer);

    [LibraryImport(LibraryName, EntryPoint = "tav_byte_buffer_len")]
    internal static partial nuint ByteBufferLength(IntPtr buffer);

    [LibraryImport(LibraryName, EntryPoint = "tav_byte_buffer_free")]
    internal static partial void ByteBufferFree(IntPtr buffer);

    [LibraryImport(LibraryName, EntryPoint = "tav_verify_snp_attestation")]
    internal static partial IntPtr VerifySnpAttestation(
        IntPtr reportBytes,
        nuint reportLength,
        IntPtr arkPem,
        nuint arkPemLength,
        IntPtr askPem,
        nuint askPemLength,
        IntPtr vcekPem,
        nuint vcekPemLength,
        out IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_version")]
    internal static partial uint SnpVersion(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_guest_svn")]
    internal static partial uint SnpGuestSvn(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy")]
    internal static partial ulong SnpPolicy(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_abi_minor")]
    internal static partial byte SnpPolicyAbiMinor(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_abi_major")]
    internal static partial byte SnpPolicyAbiMajor(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_smt")]
    internal static partial byte SnpPolicySmt(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_migrate_ma")]
    internal static partial byte SnpPolicyMigrateMa(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_debug")]
    internal static partial byte SnpPolicyDebug(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_single_socket")]
    internal static partial byte SnpPolicySingleSocket(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_cxl_allow")]
    internal static partial byte SnpPolicyCxlAllow(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_mem_aes_256_xts")]
    internal static partial byte SnpPolicyMemAes256Xts(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_rapl_dis")]
    internal static partial byte SnpPolicyRaplDis(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_ciphertext_hiding_dram")]
    internal static partial byte SnpPolicyCiphertextHidingDram(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_page_swap_disable")]
    internal static partial byte SnpPolicyPageSwapDisable(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_vmpl")]
    internal static partial uint SnpVmpl(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_signature_algo")]
    internal static partial uint SnpSignatureAlgorithm(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_platform_info")]
    internal static partial ulong SnpPlatformInfo(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_flags")]
    internal static partial uint SnpFlags(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_flags_author_key_en")]
    internal static partial byte SnpFlagsAuthorKeyEnabled(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_flags_mask_chip_key")]
    internal static partial byte SnpFlagsMaskChipKey(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_flags_signing_key")]
    internal static partial byte SnpFlagsSigningKey(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_cpuid_fam_id")]
    internal static partial byte SnpCpuidFamilyId(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_cpuid_mod_id")]
    internal static partial byte SnpCpuidModelId(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_cpuid_step")]
    internal static partial byte SnpCpuidStepping(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_current_build")]
    internal static partial byte SnpCurrentBuild(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_current_minor")]
    internal static partial byte SnpCurrentMinor(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_current_major")]
    internal static partial byte SnpCurrentMajor(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_committed_build")]
    internal static partial byte SnpCommittedBuild(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_committed_minor")]
    internal static partial byte SnpCommittedMinor(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_committed_major")]
    internal static partial byte SnpCommittedMajor(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_family_id")]
    internal static partial void SnpFamilyId(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_image_id")]
    internal static partial void SnpImageId(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_platform_version")]
    internal static partial void SnpPlatformVersion(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_report_data")]
    internal static partial void SnpReportData(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_measurement")]
    internal static partial void SnpMeasurement(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_host_data")]
    internal static partial void SnpHostData(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_id_key_digest")]
    internal static partial void SnpIdKeyDigest(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_author_key_digest")]
    internal static partial void SnpAuthorKeyDigest(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_report_id")]
    internal static partial void SnpReportId(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_report_id_ma")]
    internal static partial void SnpReportIdMa(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_reported_tcb")]
    internal static partial void SnpReportedTcb(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_chip_id")]
    internal static partial void SnpChipId(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_committed_tcb")]
    internal static partial void SnpCommittedTcb(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_launch_tcb")]
    internal static partial void SnpLaunchTcb(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_signature_r")]
    internal static partial void SnpSignatureR(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_signature_s")]
    internal static partial void SnpSignatureS(IntPtr report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_free")]
    internal static partial void SnpReportFree(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_from_bytes")]
    internal static partial IntPtr CborFromBytes(
        IntPtr bytes, nuint length, out IntPtr value);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_to_bytes")]
    internal static partial IntPtr CborToBytes(
        IntPtr value, out IntPtr bytes);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_kind")]
    internal static partial int CborKind(IntPtr value);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_int")]
    internal static partial IntPtr CborInt(IntPtr value, out long result);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_simple")]
    internal static partial IntPtr CborSimple(IntPtr value, out byte result);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_bytes")]
    internal static partial IntPtr CborBytes(
        IntPtr value, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_text")]
    internal static partial IntPtr CborText(
        IntPtr value, out IntPtr text, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_tag")]
    internal static partial IntPtr CborTag(IntPtr value, out ulong tag);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_tagged_payload")]
    internal static partial IntPtr CborTaggedPayload(
        IntPtr value, out IntPtr payload);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_len")]
    internal static partial IntPtr CborLength(IntPtr value, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_array_at")]
    internal static partial IntPtr CborArrayAt(
        IntPtr value, nuint index, out IntPtr child);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_at_int")]
    internal static partial IntPtr CborMapAtInt(
        IntPtr value, long key, out IntPtr child);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_at_text")]
    internal static partial IntPtr CborMapAtText(
        IntPtr value, IntPtr key, nuint keyLength, out IntPtr child);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_at")]
    internal static partial IntPtr CborMapAt(
        IntPtr value, IntPtr key, out IntPtr child);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_has_int_key")]
    internal static partial IntPtr CborMapHasInt(
        IntPtr value, long key, out byte result);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_has_text_key")]
    internal static partial IntPtr CborMapHasText(
        IntPtr value, IntPtr key, nuint keyLength, out byte result);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_has_key")]
    internal static partial IntPtr CborMapHas(
        IntPtr value, IntPtr key, out byte result);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_entry_at")]
    internal static partial IntPtr CborMapEntryAt(
        IntPtr value, nuint index, out IntPtr key, out IntPtr child);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_key_at")]
    internal static partial IntPtr CborMapKeyAt(
        IntPtr value, nuint index, out IntPtr key);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_value_at")]
    internal static partial IntPtr CborMapValueAt(
        IntPtr value, nuint index, out IntPtr child);

    [LibraryImport(LibraryName, EntryPoint = "tav_validate_cose_sign1")]
    internal static partial IntPtr ValidateCoseSign1(
        IntPtr value, out IntPtr sign1);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_free")]
    internal static partial void CborFree(IntPtr value);

    [LibraryImport(LibraryName, EntryPoint = "tav_verify_cose_sign1_embedded")]
    internal static partial IntPtr VerifyCoseSign1Embedded(
        IntPtr sign1, IntPtr spkiDer, nuint spkiDerLength, int coseAlgorithm);

    [LibraryImport(LibraryName, EntryPoint = "tav_verify_cose_sign1_detached")]
    internal static partial IntPtr VerifyCoseSign1Detached(
        IntPtr sign1,
        IntPtr payload,
        nuint payloadLength,
        IntPtr spkiDer,
        nuint spkiDerLength,
        int coseAlgorithm);

    [LibraryImport(LibraryName, EntryPoint = "tav_verify_caci_uvm_endorsement")]
    internal static partial IntPtr VerifyCaciUvmEndorsement(
        IntPtr uvmEndorsement,
        nuint uvmEndorsementLength,
        IntPtr trustedDidX509,
        nuint trustedDidX509Length,
        out IntPtr value);

    [LibraryImport(LibraryName, EntryPoint = "tav_verify_caci_attestation")]
    internal static partial IntPtr VerifyCaciAttestation(
        IntPtr attestation,
        IntPtr minimumTcbCpuids,
        IntPtr minimumTcbValues,
        nuint minimumTcbCount,
        IntPtr trustedPolicyDigests,
        nuint trustedPolicyDigestCount,
        IntPtr uvmEndorsement,
        IntPtr uvmFeed,
        nuint uvmFeedLength,
        ulong minimumSvn,
        out IntPtr reportData);
}
