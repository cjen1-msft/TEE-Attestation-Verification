// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace TeeAttestationVerification;

/// <summary>Provides synchronous SNP, CACI, and certificate helper operations.</summary>
public static class AttestationVerifier
{
    private const int TcbVersionLength = 8;
    private const int MaximumMinimumTcbEntries =
        NativeResult.MaximumInputLength / TcbVersionLength;

    private static readonly Regex PemCertificatePattern = new(
        "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----",
        RegexOptions.CultureInvariant);

    /// <summary>Splits a PEM bundle into normalized certificate PEM strings.</summary>
    /// <param name="pemBundle">One or more concatenated PEM certificate blocks.</param>
    /// <returns>The certificates in source order.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pemBundle"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="pemBundle"/> is empty.</exception>
    /// <exception cref="FormatException">The bundle is malformed or contains non-certificate content.</exception>
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

    /// <summary>Authenticates an AMD SEV-SNP report and returns its verified claims.</summary>
    /// <param name="reportBytes">The binary SNP attestation report.</param>
    /// <param name="arkPem">The AMD root key certificate in PEM form.</param>
    /// <param name="askPem">The AMD signing key certificate in PEM form.</param>
    /// <param name="vcekPem">The VCEK leaf certificate in PEM form.</param>
    /// <returns>An owned verified report. Dispose it after use.</returns>
    /// <exception cref="VerifyException">Native parsing or verification fails.</exception>
    public static unsafe SnpAttestationReport VerifySnpAttestation(
        ReadOnlyMemory<byte> reportBytes,
        string arkPem,
        string askPem,
        string vcekPem)
    {
        byte[] report = NativeResult.Snapshot(reportBytes, nameof(reportBytes));
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

    private static void RequireOnlyWhitespace(ReadOnlySpan<char> content)
    {
        if (!content.Trim().IsEmpty)
        {
            throw new FormatException(
                "Failed to parse certificate bundle PEM: unexpected content outside certificate blocks.");
        }
    }

    /// <summary>Authenticates a CACI UVM endorsement against a trusted DID x509 policy.</summary>
    /// <param name="uvmEndorsement">The encoded COSE UVM endorsement.</param>
    /// <param name="trustedDidX509">The trusted DID x509 policy string.</param>
    /// <returns>An owned verified CBOR endorsement. Dispose it after use.</returns>
    /// <exception cref="VerifyException">Native parsing or verification fails.</exception>
    public static CborValue VerifyUvmEndorsement(
        ReadOnlyMemory<byte> uvmEndorsement,
        string trustedDidX509)
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
    }

    /// <summary>
    /// Applies the CACI relying-party policy to verified SNP and UVM artifacts.
    /// </summary>
    /// <param name="attestation">A report returned by <see cref="VerifySnpAttestation"/>.</param>
    /// <param name="minimumTcb">
    /// CPUID and eight-byte TCB pairs, or an empty sequence for no minimum. The
    /// Milan/Genoa byte layout is [boot loader, TEE, reserved x4, SNP, microcode];
    /// Turin is [FMC, boot loader, TEE, SNP, reserved x3, microcode]. Duplicate
    /// CPUIDs are rejected. The sequence and TCB bytes are copied before entering
    /// native code.
    /// </param>
    /// <param name="trustedCaciExecutionPolicies">Trusted CACI execution-policy digests.</param>
    /// <param name="uvm">A value returned by <see cref="VerifyUvmEndorsement"/>.</param>
    /// <param name="uvmFeed">The required UVM feed identifier.</param>
    /// <param name="minimumSvn">The minimum accepted UVM security version number.</param>
    /// <returns>A copy of the verified 64-byte SNP report data.</returns>
    /// <exception cref="ArgumentNullException">A required reference argument is null.</exception>
    /// <exception cref="ArgumentException">
    /// A TCB value is not eight bytes or a CPUID occurs more than once.
    /// </exception>
    /// <exception cref="VerifyException">Native policy verification fails.</exception>
    public static byte[] VerifyCaciAttestation(
        SnpAttestationReport attestation,
        IEnumerable<(uint Cpuid, ReadOnlyMemory<byte> Tcb)> minimumTcb,
        CACIPolicyDigests trustedCaciExecutionPolicies,
        CborValue uvm,
        string uvmFeed,
        ulong minimumSvn)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        ArgumentNullException.ThrowIfNull(minimumTcb);
        ArgumentNullException.ThrowIfNull(trustedCaciExecutionPolicies);
        ArgumentNullException.ThrowIfNull(uvm);
        (uint[] cpuids, byte[] tcbValues) = SnapshotMinimumTcb(minimumTcb);
        ReadOnlySpan<byte> policies = trustedCaciExecutionPolicies.Bytes;
        byte[] feed = NativeResult.Utf8(uvmFeed, nameof(uvmFeed));

        unsafe
        {
            fixed (uint* cpuidsPointer = cpuids)
            fixed (byte* tcbValuesPointer = tcbValues)
            fixed (byte* policiesPointer = policies)
            fixed (byte* feedPointer = feed)
            {
                IntPtr error = NativeMethods.VerifyCaciAttestation(
                    attestation.Handle,
                    (IntPtr)cpuidsPointer,
                    (IntPtr)tcbValuesPointer,
                    (nuint)cpuids.Length,
                    (IntPtr)policiesPointer,
                    (nuint)trustedCaciExecutionPolicies.Count,
                    uvm.Handle,
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
    }

    private static (uint[] Cpuids, byte[] Values) SnapshotMinimumTcb(
        IEnumerable<(uint Cpuid, ReadOnlyMemory<byte> Tcb)> minimumTcb)
    {
        bool hasCount = minimumTcb.TryGetNonEnumeratedCount(out int count);
        if (!hasCount &&
            minimumTcb is IReadOnlyCollection<(uint Cpuid, ReadOnlyMemory<byte> Tcb)> collection)
        {
            count = collection.Count;
            hasCount = true;
        }

        if (hasCount && count > MaximumMinimumTcbEntries)
        {
            throw new ArgumentOutOfRangeException(
                nameof(minimumTcb),
                $"Minimum TCB exceeds the {MaximumMinimumTcbEntries}-entry maximum.");
        }

        (uint Cpuid, ReadOnlyMemory<byte> Tcb)[] entries = minimumTcb.ToArray();
        if (entries.Length > MaximumMinimumTcbEntries)
        {
            throw new ArgumentOutOfRangeException(
                nameof(minimumTcb),
                $"Minimum TCB exceeds the {MaximumMinimumTcbEntries}-entry maximum.");
        }

        uint[] cpuids = new uint[entries.Length];
        byte[] values = new byte[entries.Length * TcbVersionLength];
        HashSet<uint> seen = [];

        for (int index = 0; index < entries.Length; index++)
        {
            (uint cpuid, ReadOnlyMemory<byte> tcb) = entries[index];
            if (!seen.Add(cpuid))
            {
                throw new ArgumentException(
                    $"Duplicate minimum TCB CPUID 0x{cpuid:x8}.",
                    nameof(minimumTcb));
            }
            if (tcb.Length != TcbVersionLength)
            {
                throw new ArgumentException(
                    $"Minimum TCB at index {index} must be {TcbVersionLength} bytes, got {tcb.Length}.",
                    nameof(minimumTcb));
            }

            cpuids[index] = cpuid;
            tcb.Span.CopyTo(values.AsSpan(index * TcbVersionLength, TcbVersionLength));
        }

        return (cpuids, values);
    }

}
