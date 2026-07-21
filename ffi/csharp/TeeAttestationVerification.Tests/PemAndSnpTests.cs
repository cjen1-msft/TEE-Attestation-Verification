// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Buffers;
using System.Text;

namespace TeeAttestationVerification.Tests;

public sealed class PemAndSnpTests
{
    [Fact]
    public void SplitPemBundleAndDeprecatedAliasSplitAndValidateCertificates()
    {
        MilanInputs input = FixtureData.LoadMilan();
        string bundle = $"{input.Ask}\n{input.Ark}";

        IReadOnlyList<string> split = AttestationVerifier.SplitPemBundle(bundle);
#pragma warning disable CS0618
        IReadOnlyList<string> deprecatedSplit =
            AttestationVerifier.SplitCertificateBundle(bundle);
#pragma warning restore CS0618

        Assert.Equal(2, split.Count);
        Assert.Equal(split, deprecatedSplit);
        Assert.All(split, pem =>
        {
            Assert.StartsWith("-----BEGIN CERTIFICATE-----", pem);
            Assert.EndsWith("-----END CERTIFICATE-----", pem.TrimEnd());
            Assert.NotEmpty(FixtureData.PemToDer(pem));
        });
        Assert.Throws<ArgumentException>(() => AttestationVerifier.SplitPemBundle(""));
        Assert.Throws<FormatException>(() => AttestationVerifier.SplitPemBundle("not a pem"));
        Assert.Throws<FormatException>(() =>
            AttestationVerifier.SplitPemBundle($"junk\n{bundle}"));
        Assert.Throws<FormatException>(() =>
            AttestationVerifier.SplitPemBundle(
                $"{input.Ask}\n-----BEGIN PRIVATE KEY-----\nAA==\n" +
                $"-----END PRIVATE KEY-----\n{input.Ark}"));
        Assert.Throws<ArgumentNullException>(() => AttestationVerifier.SplitPemBundle(null!));
    }

    [Fact]
    public async Task PemEndorsementSequenceIsAcceptedAndVerified()
    {
        MilanInputs input = FixtureData.LoadMilan();
        ReadOnlyMemory<byte>[] endorsements =
        [
            Encoding.UTF8.GetBytes(input.Vcek),
            Encoding.UTF8.GetBytes(input.Ask),
            Encoding.UTF8.GetBytes(input.Ark),
        ];

        using SnpAttestationReport report =
            await AttestationVerifier.VerifySnpAttestationWithCertChainAsync(
                input.Report, endorsements);

        Assert.Equal(3u, report.Version);
    }

    [Fact]
    public async Task VerifyAttestationAndEveryReportAccessorUseNativeGolden()
    {
        MilanInputs input = FixtureData.LoadMilan();
        Task<SnpAttestationReport> verification = AttestationVerifier.VerifyAttestationAsync(
            input.Report, input.Ark, input.Ask, input.Vcek);
        Assert.True(verification.IsCompleted);
        using SnpAttestationReport report = await verification;

        Assert.Equal(3u, report.Version);
        Assert.Equal(2u, report.GuestSvn);
        Assert.Equal(0x3001ful, report.Policy);
        Assert.Equal(31, report.PolicyAbiMinor);
        Assert.Equal(0, report.PolicyAbiMajor);
        Assert.True(report.PolicySmt);
        Assert.False(report.PolicyMigrateMa);
        Assert.False(report.PolicyDebug);
        Assert.False(report.PolicySingleSocket);
        Assert.False(report.PolicyCxlAllow);
        Assert.False(report.PolicyMemAes256Xts);
        Assert.False(report.PolicyRaplDis);
        Assert.False(report.PolicyCiphertextHidingDram);
        Assert.False(report.PolicyPageSwapDisable);
        Assert.Equal(0u, report.Vmpl);
        Assert.Equal(1u, report.SignatureAlgorithm);
        Assert.Equal(0x25ul, report.PlatformInfo);
        Assert.Equal(0u, report.Flags);
        Assert.False(report.FlagsAuthorKeyEnabled);
        Assert.False(report.FlagsMaskChipKey);
        Assert.Equal(0, report.FlagsSigningKey);
        Assert.Equal(25, report.CpuidFamilyId);
        Assert.Equal(1, report.CpuidModelId);
        Assert.Equal(1, report.CpuidStepping);
        Assert.Equal(29, report.CurrentBuild);
        Assert.Equal(55, report.CurrentMinor);
        Assert.Equal(1, report.CurrentMajor);
        Assert.Equal(29, report.CommittedBuild);
        Assert.Equal(55, report.CommittedMinor);
        Assert.Equal(1, report.CommittedMajor);

        Assert.Equal("01000000000000000000000000000000", Hex(report.FamilyId));
        Assert.Equal("02000000000000000000000000000000", Hex(report.ImageId));
        Assert.Equal("04000000000018db", Hex(report.PlatformVersion));
        Assert.Equal(new string('0', 128), Hex(report.ReportData));
        Assert.Equal(
            "5feee30d6d7e1a29f403d70a4198237ddfb13051a2d6976439487c609388ed7f98189887920ab2fa0096903a0c23fca1",
            Hex(report.Measurement));
        Assert.Equal(
            "4f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d10",
            Hex(report.HostData));
        Assert.Equal(48, report.IdKeyDigest.Length);
        Assert.Equal(new string('0', 96), Hex(report.AuthorKeyDigest));
        Assert.Equal(
            "5e01036273418d910bdca3f5cb9c7d849e88e2141483eb6cc9afd794ffbbbcbc",
            Hex(report.ReportId));
        Assert.Equal(new string('f', 64), Hex(report.ReportIdMa));
        Assert.Equal("04000000000018db", Hex(report.ReportedTcb));
        Assert.Equal(
            "4ffb5cb4fd594f3fee6528fc3fb10370bb38abe89dcd5ba2cf0ab6a11df2ca282add516bef45a890a8c9f9732bdca68f9f3f16c42e846030a800295dbeb19ba5",
            Hex(report.ChipId));
        Assert.Equal("04000000000018db", Hex(report.CommittedTcb));
        Assert.Equal("04000000000018db", Hex(report.LaunchTcb));
        Assert.Equal(72, report.SignatureR.Length);
        Assert.Equal(72, report.SignatureS.Length);

        report.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = report.Version);
    }

    [Fact]
    public async Task VerifyAttestationMapsEveryNativeErrorToVerifyException()
    {
        MilanInputs input = FixtureData.LoadMilan();
        VerifyException invalidRoot = await Assert.ThrowsAsync<VerifyException>(() =>
            AttestationVerifier.VerifyAttestationAsync(
                input.Report, input.Ask, input.Ask, input.Vcek));
        Assert.Equal(ErrorCode.InvalidRootCertificate, invalidRoot.Code);
        Assert.NotEmpty(invalidRoot.Message);

        byte[] tampered = (byte[])input.Report.Clone();
        tampered[0x90] ^= 0xff;
        VerifyException badSignature = await Assert.ThrowsAsync<VerifyException>(() =>
            AttestationVerifier.VerifyAttestationAsync(
                tampered, input.Ark, input.Ask, input.Vcek));
        Assert.Equal(ErrorCode.SignatureVerificationError, badSignature.Code);

        VerifyException empty = await Assert.ThrowsAsync<VerifyException>(() =>
            AttestationVerifier.VerifyAttestationAsync(
                ReadOnlyMemory<byte>.Empty, input.Ark, input.Ask, input.Vcek));
        Assert.Equal(ErrorCode.InvalidArgument, empty.Code);

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            AttestationVerifier.VerifyAttestationAsync(
                input.Report, null!, input.Ask, input.Vcek));

        using OversizedMemoryManager oversized = new();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            AttestationVerifier.VerifyAttestationAsync(
                oversized.Value, input.Ark, input.Ask, input.Vcek));
    }

    [Fact]
    public async Task DerEndorsementSequenceIsConvertedAndVerified()
    {
        MilanInputs input = FixtureData.LoadMilan();
        ReadOnlyMemory<byte>[] endorsements =
        [
            FixtureData.PemToDer(input.Vcek),
            FixtureData.PemToDer(input.Ask),
            FixtureData.PemToDer(input.Ark),
        ];

        Task<SnpAttestationReport> verification =
            AttestationVerifier.VerifySnpAttestationWithCertChainAsync(
                input.Report, endorsements);
        Assert.True(verification.IsCompleted);
        using SnpAttestationReport report = await verification;
        Assert.Equal(3u, report.Version);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            AttestationVerifier.VerifySnpAttestationWithCertChainAsync(
                input.Report, endorsements[..2]));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            AttestationVerifier.VerifySnpAttestationWithCertChainAsync(
                input.Report, [ReadOnlyMemory<byte>.Empty, endorsements[1], endorsements[2]]));
    }

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private sealed class OversizedMemoryManager : MemoryManager<byte>
    {
        internal ReadOnlyMemory<byte> Value => CreateMemory((1024 * 1024 * 1024) + 1);

        public override Span<byte> GetSpan() =>
            throw new InvalidOperationException("Oversized input must be rejected before access.");

        public override MemoryHandle Pin(int elementIndex = 0) =>
            throw new InvalidOperationException("Oversized input must be rejected before pinning.");

        public override void Unpin()
        {
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
