// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace TeeAttestationVerification.Tests;

public sealed class CaciTests
{
    [Fact]
    public async Task FullCaciVerificationAndEveryFacadeMemberCallNativeAbi()
    {
        CaciInputs input = FixtureData.LoadCaci();
        using SnpAttestationReport attestation =
            await AttestationVerifier.VerifySnpAttestationWithCertChainAsync(
                input.Report,
                input.Endorsements.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray());

        Task<CborValue> uvmVerification = AttestationVerifier.VerifyUvmEndorsementAsync(
            input.UvmEndorsement, FixtureData.TrustedDidX509);
        Assert.True(uvmVerification.IsCompleted);
        using CborValue uvm = await uvmVerification;
        using CoseSign1 sign1 = uvm.AsCoseSign1();
        Assert.NotEmpty(sign1.Payload());

        Task<byte[]> verification = AttestationVerifier.VerifyCaciAttestation(
            attestation,
            input.MinimumTcbJson,
            input.Policies.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray(),
            uvm,
            input.UvmFeed,
            input.MinimumSvn);
        Assert.True(verification.IsCompleted);
        byte[] reportData = await verification;

        Assert.Equal(64, reportData.Length);
        Assert.Equal(attestation.ReportData, reportData);

        byte[] withoutMinimumTcb = await AttestationVerifier.VerifyCaciAttestation(
            attestation,
            "",
            input.Policies.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray(),
            uvm,
            input.UvmFeed,
            input.MinimumSvn);
        Assert.Equal(reportData, withoutMinimumTcb);
    }

    [Fact]
    public async Task CaciErrorsPreserveNativeCodesAndManagedPolicyValidation()
    {
        CaciInputs input = FixtureData.LoadCaci();
        using SnpAttestationReport attestation =
            await AttestationVerifier.VerifySnpAttestationWithCertChainAsync(
                input.Report,
                input.Endorsements.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray());
        using CborValue uvm = await AttestationVerifier.VerifyUvmEndorsementAsync(
            input.UvmEndorsement, FixtureData.TrustedDidX509);

        VerifyException didError = await Assert.ThrowsAsync<VerifyException>(() =>
            AttestationVerifier.VerifyUvmEndorsementAsync(
                input.UvmEndorsement,
                "did:x509:0:sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                "::eku:1.3.6.1.4.1.311.76.59.1.2"));
        Assert.Equal(ErrorCode.CaciDidX509, didError.Code);
        Assert.NotEmpty(didError.Message);

        VerifyException emptyUvm = await Assert.ThrowsAsync<VerifyException>(() =>
            AttestationVerifier.VerifyUvmEndorsementAsync(
                ReadOnlyMemory<byte>.Empty, FixtureData.TrustedDidX509));
        Assert.Equal(ErrorCode.InvalidArgument, emptyUvm.Code);

        byte[] untrustedPolicy = (byte[])input.Policies[0].Clone();
        untrustedPolicy[0] ^= 0xff;
        VerifyException policyError = await Assert.ThrowsAsync<VerifyException>(() =>
            AttestationVerifier.VerifyCaciAttestation(
                attestation,
                input.MinimumTcbJson,
                new ReadOnlyMemory<byte>[] { untrustedPolicy },
                uvm,
                input.UvmFeed,
                input.MinimumSvn));
        Assert.Equal(ErrorCode.CaciPolicy, policyError.Code);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            AttestationVerifier.VerifyCaciAttestation(
                attestation, input.MinimumTcbJson, [], uvm, input.UvmFeed, input.MinimumSvn));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            AttestationVerifier.VerifyCaciAttestation(
                attestation, """{"bad":"04000000000018db"}""",
                input.Policies.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray(),
                uvm, input.UvmFeed, input.MinimumSvn));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            AttestationVerifier.VerifyCaciAttestation(
                attestation, """{"00a00f11":"00"}""",
                input.Policies.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray(),
                uvm, input.UvmFeed, input.MinimumSvn));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            AttestationVerifier.VerifyCaciAttestation(
                attestation, input.MinimumTcbJson, new ReadOnlyMemory<byte>[] { new byte[31] },
                uvm, input.UvmFeed, input.MinimumSvn));
    }

    [Fact]
    public async Task DuplicateMinimumTcbCpuidUsesLastValue()
    {
        CaciInputs input = FixtureData.LoadCaci();
        using SnpAttestationReport attestation =
            await AttestationVerifier.VerifySnpAttestationWithCertChainAsync(
                input.Report,
                input.Endorsements.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray());
        using CborValue uvm = await AttestationVerifier.VerifyUvmEndorsementAsync(
            input.UvmEndorsement, FixtureData.TrustedDidX509);

        byte[] reportData = await AttestationVerifier.VerifyCaciAttestation(
            attestation,
            """
            {
              "00a00f11": "ffffffffffffffff",
              "00a00f11": "04000000000018db"
            }
            """,
            input.Policies.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray(),
            uvm,
            input.UvmFeed,
            input.MinimumSvn);

        Assert.Equal(attestation.ReportData, reportData);
    }
}
