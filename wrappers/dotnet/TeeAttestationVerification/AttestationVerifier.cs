// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TeeAttestationVerification;

public static class AttestationVerifier
{
    private const int TcbVersionLength = 8;
    private const int PolicyDigestLength = 32;

    private static readonly Regex PemCertificatePattern = new(
        "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----",
        RegexOptions.CultureInvariant);

    public static IReadOnlyList<string> SplitPemBundle(string pemBundle)
    {
        ArgumentNullException.ThrowIfNull(pemBundle);
        if (string.IsNullOrWhiteSpace(pemBundle))
        {
            throw new ArgumentException("Certificate bundle PEM is empty.", nameof(pemBundle));
        }

        List<string> certificates = [];
        int consumed = 0;
        foreach (Match match in PemCertificatePattern.Matches(pemBundle))
        {
            RequireOnlyWhitespace(
                pemBundle.AsSpan(consumed, match.Index - consumed));
            try
            {
                using X509Certificate2 certificate = X509Certificate2.CreateFromPem(match.Value);
                certificates.Add(certificate.ExportCertificatePem());
            }
            catch (CryptographicException exception)
            {
                throw new FormatException(
                    $"Failed to parse certificate bundle PEM: {exception.Message}",
                    exception);
            }

            consumed = match.Index + match.Length;
        }

        if (certificates.Count == 0)
        {
            throw new FormatException("Failed to parse certificate bundle PEM: no certificates found.");
        }

        RequireOnlyWhitespace(pemBundle.AsSpan(consumed));
        return certificates.AsReadOnly();
    }

    [Obsolete("Use SplitPemBundle instead.")]
    public static IReadOnlyList<string> SplitCertificateBundle(string pemBundle) =>
        SplitPemBundle(pemBundle);

    public static Task<SnpAttestationReport> VerifyAttestationAsync(
        ReadOnlyMemory<byte> reportBytes,
        string arkPem,
        string askPem,
        string vcekPem)
    {
        return NativeResult.Complete(() =>
        {
            byte[] report = NativeResult.Snapshot(reportBytes, nameof(reportBytes));
            return VerifyAttestationCore(report, arkPem, askPem, vcekPem);
        });
    }

    public static Task<SnpAttestationReport> VerifySnpAttestationWithCertChainAsync(
        ReadOnlyMemory<byte> attestationReport,
        IReadOnlyList<ReadOnlyMemory<byte>> amdEndorsements)
    {
        return NativeResult.Complete(() =>
        {
            ArgumentNullException.ThrowIfNull(amdEndorsements);
            if (amdEndorsements.Count != 3)
            {
                throw new ArgumentException(
                    $"Expected AMD endorsements [vcek, ask, ark], got {amdEndorsements.Count} certificate(s).",
                    nameof(amdEndorsements));
            }

            string[] pem = new string[3];
            for (int index = 0; index < pem.Length; index++)
            {
                byte[] endorsement = NativeResult.Snapshot(
                    amdEndorsements[index], $"{nameof(amdEndorsements)}[{index}]");
                if (endorsement.Length == 0)
                {
                    throw new ArgumentException(
                        $"AMD endorsement at index {index} is empty.",
                        nameof(amdEndorsements));
                }

                pem[index] = EndorsementToPem(endorsement, index);
            }

            byte[] report = NativeResult.Snapshot(attestationReport, nameof(attestationReport));
            return VerifyAttestationCore(report, pem[2], pem[1], pem[0]);
        });
    }

    private static void RequireOnlyWhitespace(ReadOnlySpan<char> content)
    {
        if (!content.Trim().IsEmpty)
        {
            throw new FormatException(
                "Failed to parse certificate bundle PEM: unexpected content outside certificate blocks.");
        }
    }

    private static string EndorsementToPem(byte[] endorsement, int index)
    {
        try
        {
            string text = new UTF8Encoding(
                encoderShouldEmitUTF8Identifier: false,
                throwOnInvalidBytes: true).GetString(endorsement);
            using X509Certificate2 certificate = X509Certificate2.CreateFromPem(text);
            return certificate.ExportCertificatePem();
        }
        catch (DecoderFallbackException)
        {
        }
        catch (CryptographicException)
        {
        }

        try
        {
            using X509Certificate2 certificate = new(endorsement);
            return certificate.ExportCertificatePem();
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException(
                $"AMD endorsement at index {index} is not a valid PEM or DER certificate.",
                "amdEndorsements",
                exception);
        }
    }

    public static Task<CborValue> VerifyUvmEndorsementAsync(
        ReadOnlyMemory<byte> uvmEndorsement,
        string trustedDidX509)
    {
        return NativeResult.Complete(() =>
        {
            byte[] endorsement = NativeResult.Snapshot(
                uvmEndorsement, nameof(uvmEndorsement));
            byte[] trustedDid = NativeResult.Utf8(trustedDidX509, nameof(trustedDidX509));
            unsafe
            {
                fixed (byte* endorsementPointer = endorsement)
                fixed (byte* trustedDidPointer = trustedDid)
                {
                    IntPtr error = NativeMethods.VerifyCaciUvmEndorsement(
                        (IntPtr)endorsementPointer,
                        (nuint)endorsement.Length,
                        (IntPtr)trustedDidPointer,
                        (nuint)trustedDid.Length,
                        out IntPtr value);
                    NativeResult.ThrowIfError(error);
                    return CborValue.FromOwnedHandle(value);
                }
            }
        });
    }

    public static Task<byte[]> VerifyCaciAttestation(
        SnpAttestationReport attestation,
        string minimumTcbJson,
        IReadOnlyList<ReadOnlyMemory<byte>> trustedCaciExecutionPolicies,
        CborValue uvm,
        string uvmFeed,
        ulong minimumSvn)
    {
        return NativeResult.Complete(() =>
        {
            ArgumentNullException.ThrowIfNull(attestation);
            ArgumentNullException.ThrowIfNull(uvm);
            (uint[] cpuids, byte[] tcbValues) = ParseMinimumTcb(minimumTcbJson);
            (byte[] policies, int policyCount) = SnapshotPolicies(
                trustedCaciExecutionPolicies);
            byte[] feed = NativeResult.Utf8(uvmFeed, nameof(uvmFeed));

            using SafeHandleLease attestationLease = attestation.AcquireHandle();
            using CborNativeLease uvmLease = uvm.AcquireNative();
            unsafe
            {
                fixed (uint* cpuidsPointer = cpuids)
                fixed (byte* tcbValuesPointer = tcbValues)
                fixed (byte* policiesPointer = policies)
                fixed (byte* feedPointer = feed)
                {
                    IntPtr error = NativeMethods.VerifyCaciAttestation(
                        attestationLease.Pointer,
                        (IntPtr)cpuidsPointer,
                        (IntPtr)tcbValuesPointer,
                        (nuint)cpuids.Length,
                        (IntPtr)policiesPointer,
                        (nuint)policyCount,
                        uvmLease.Pointer,
                        (IntPtr)feedPointer,
                        (nuint)feed.Length,
                        minimumSvn,
                        out IntPtr reportData);
                    NativeResult.ThrowIfError(error);
                    if (reportData == IntPtr.Zero)
                    {
                        throw new InvalidOperationException(
                            "Native CACI verification returned a null report-data buffer.");
                    }

                    return NativeResult.CopyOwnedBytes(reportData);
                }
            }
        });
    }

    private static unsafe SnpAttestationReport VerifyAttestationCore(
        byte[] report,
        string arkPem,
        string askPem,
        string vcekPem)
    {
        byte[] ark = NativeResult.Utf8(arkPem, nameof(arkPem));
        byte[] ask = NativeResult.Utf8(askPem, nameof(askPem));
        byte[] vcek = NativeResult.Utf8(vcekPem, nameof(vcekPem));
        fixed (byte* reportPointer = report)
        fixed (byte* arkPointer = ark)
        fixed (byte* askPointer = ask)
        fixed (byte* vcekPointer = vcek)
        {
            IntPtr error = NativeMethods.VerifySnpAttestation(
                (IntPtr)reportPointer,
                (nuint)report.Length,
                (IntPtr)arkPointer,
                (nuint)ark.Length,
                (IntPtr)askPointer,
                (nuint)ask.Length,
                (IntPtr)vcekPointer,
                (nuint)vcek.Length,
                out IntPtr verifiedReport);
            NativeResult.ThrowIfError(error);
            return new SnpAttestationReport(verifiedReport);
        }
    }

    private static (uint[] Cpuids, byte[] Values) ParseMinimumTcb(string minimumTcbJson)
    {
        ArgumentNullException.ThrowIfNull(minimumTcbJson);
        if (string.IsNullOrWhiteSpace(minimumTcbJson))
        {
            return ([], []);
        }

        NativeResult.ValidateLength(
            System.Text.Encoding.UTF8.GetByteCount(minimumTcbJson),
            nameof(minimumTcbJson));

        try
        {
            using JsonDocument document = JsonDocument.Parse(minimumTcbJson);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new ArgumentException(
                    "Minimum TCB JSON must be an object.",
                    nameof(minimumTcbJson));
            }

            SortedDictionary<uint, (string Cpuid, string Tcb)> entries = [];
            foreach (JsonProperty property in document.RootElement.EnumerateObject())
            {
                if (property.Name.Length != 8 ||
                    !uint.TryParse(
                        property.Name,
                        NumberStyles.AllowHexSpecifier,
                        CultureInfo.InvariantCulture,
                        out uint cpuid))
                {
                    throw new ArgumentException(
                        $"CPUID must be 8 hex characters, got {property.Name.Length}.",
                        nameof(minimumTcbJson));
                }

                if (property.Value.ValueKind != JsonValueKind.String)
                {
                    throw new ArgumentException(
                        $"TCB version for CPUID {property.Name} must be a hex string.",
                        nameof(minimumTcbJson));
                }

                entries[cpuid] = (property.Name, property.Value.GetString()!);
            }

            uint[] cpuids = new uint[entries.Count];
            byte[] values = new byte[entries.Count * TcbVersionLength];
            int index = 0;
            foreach ((uint cpuid, (string cpuidHex, string tcbHex)) in entries)
            {
                if (tcbHex.Length != TcbVersionLength * 2)
                {
                    throw new ArgumentException(
                        $"TCB version must be {TcbVersionLength} bytes, got {tcbHex.Length / 2}.",
                        nameof(minimumTcbJson));
                }

                byte[] tcb;
                try
                {
                    tcb = Convert.FromHexString(tcbHex);
                }
                catch (FormatException exception)
                {
                    throw new ArgumentException(
                        $"TCB version for CPUID {cpuidHex} is not valid hex.",
                        nameof(minimumTcbJson),
                        exception);
                }

                cpuids[index] = cpuid;
                tcb.CopyTo(values, index * TcbVersionLength);
                index++;
            }

            return (cpuids, values);
        }
        catch (JsonException exception)
        {
            throw new ArgumentException(
                $"Failed to parse minimum TCB JSON: {exception.Message}",
                nameof(minimumTcbJson),
                exception);
        }
    }

    private static (byte[] Policies, int Count) SnapshotPolicies(
        IReadOnlyList<ReadOnlyMemory<byte>> trustedCaciExecutionPolicies)
    {
        ArgumentNullException.ThrowIfNull(trustedCaciExecutionPolicies);
        if (trustedCaciExecutionPolicies.Count == 0)
        {
            throw new ArgumentException(
                "At least one trusted CACI execution policy digest is required.",
                nameof(trustedCaciExecutionPolicies));
        }

        if (trustedCaciExecutionPolicies.Count >
            NativeResult.MaximumInputLength / PolicyDigestLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(trustedCaciExecutionPolicies),
                "Trusted policy digests exceed the maximum input size.");
        }

        byte[] flattened =
            new byte[trustedCaciExecutionPolicies.Count * PolicyDigestLength];
        for (int index = 0; index < trustedCaciExecutionPolicies.Count; index++)
        {
            ReadOnlyMemory<byte> policy = trustedCaciExecutionPolicies[index];
            if (policy.Length != PolicyDigestLength)
            {
                throw new ArgumentException(
                    $"Trusted CACI execution policy digest must be {PolicyDigestLength} bytes, got {policy.Length}.",
                    nameof(trustedCaciExecutionPolicies));
            }

            policy.Span.CopyTo(
                flattened.AsSpan(index * PolicyDigestLength, PolicyDigestLength));
        }

        return (flattened, trustedCaciExecutionPolicies.Count);
    }
}
