// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using TeeAttestationVerification;

// COSE protected-header parameter label for the content type (RFC 8152).
const int CoseHeaderContentType = 3;

// The Milan fixture pins a single minimum-TCB entry: CPUID 0x00A00F11 with
// minimum TCB bytes 04000000000018db. The library accepts the minimum-TCB
// policy as parallel (CPUID, 8-byte TCB) pairs.
const uint MinimumTcbCpuid = 0x00A00F11;
byte[] minimumTcbValue = [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0xdb];

if (args.Length != 7)
{
    Console.Error.WriteLine(
        "usage: TavCaciCsharpDemo <report.hex> <host-amd-cert.base64> " +
        "<uvm.base64> <trusted-didx509> <policy.hex> <uvm-feed> <minimum-svn>");
    return 1;
}

string reportPath = args[0];
string hostAmdCertPath = args[1];
string uvmPath = args[2];
string trustedDidX509 = args[3];
string policyPath = args[4];
string uvmFeed = args[5];
string minimumSvnText = args[6];

byte[] report = ReadHex(reportPath);
byte[] uvmEndorsement = ReadBase64(uvmPath);
byte[] policy = ReadHex(policyPath);

// The host AMD certificate file is base64-encoded JSON carrying the VCEK leaf
// certificate and the ASK/ARK certificate chain that signs the SNP report.
using JsonDocument hostAmdCert = JsonDocument.Parse(ReadBase64(hostAmdCertPath));
string vcekPem = hostAmdCert.RootElement.GetProperty("vcekCert").GetString()!;
string chainPem = hostAmdCert.RootElement.GetProperty("certificateChain").GetString()!;
IReadOnlyList<string> chain = AttestationVerifier.SplitPemBundle(chainPem);
if (chain.Count < 2)
{
    Console.Error.WriteLine("certificateChain must contain the ASK and ARK certificates");
    return 1;
}

string askPem = chain[0];
string arkPem = chain[1];

const int PolicyDigestLength = 32;
if (policy.Length == 0 || policy.Length % PolicyDigestLength != 0)
{
    Console.Error.WriteLine(
        $"policy.hex must contain one or more {PolicyDigestLength}-byte policy digests");
    return 1;
}

int policyDigestCount = policy.Length / PolicyDigestLength;
ReadOnlyMemory<byte>[] trustedPolicies = Enumerable.Range(0, policyDigestCount)
    .Select(index => (ReadOnlyMemory<byte>)policy
        .AsMemory(index * PolicyDigestLength, PolicyDigestLength))
    .ToArray();

ulong minimumSvn = ulong.Parse(minimumSvnText);
(uint Cpuid, ReadOnlyMemory<byte> Tcb)[] minimumTcb = [(MinimumTcbCpuid, minimumTcbValue)];

// Every returned object owns a native handle; dispose them with `using`.
using SnpAttestationReport attestation = VerifySnpAttestation(report, arkPem, askPem, vcekPem);
using CborValue uvm = VerifyUvmEndorsement(uvmEndorsement, trustedDidX509);
byte[] verifiedReportData = VerifyCaciAttestation(
    attestation, minimumTcb, trustedPolicies, uvm, uvmFeed, minimumSvn);

Console.WriteLine("Confidential CACI attestation verified.");
Console.WriteLine("verified_report_data");
PrintHexLines(verifiedReportData, indent: 2);

Console.WriteLine("verified_snp_attestation");
PrintReportField("host_data", attestation.HostData());
PrintReportField("report_data", attestation.ReportData());
PrintReportField("measurement", attestation.Measurement());
PrintReportField("reported_tcb", attestation.ReportedTcb());

Console.WriteLine("verified_uvm_endorsement");
PrintUvmEndorsement(uvm);

Console.WriteLine("policy_digest_count");
Console.WriteLine($"  {policyDigestCount}");

Console.WriteLine("minimum_tcb");
foreach ((uint cpuid, ReadOnlyMemory<byte> tcb) in minimumTcb)
{
    Console.WriteLine($"  cpuid: 0x{cpuid:x8}");
    Console.WriteLine("  tcb");
    PrintHexLines(tcb.ToArray(), indent: 4);
}

Console.WriteLine("uvm_feed");
Console.WriteLine($"  {uvmFeed}");

Console.WriteLine("minimum_svn");
Console.WriteLine($"  {minimumSvn}");

return 0;

// Reads a file of hexadecimal text (ignoring whitespace) into raw bytes.
static byte[] ReadHex(string path) =>
    Convert.FromHexString(RemoveWhitespace(File.ReadAllText(path)));

// Reads a file of base64 text (ignoring whitespace) into raw bytes.
static byte[] ReadBase64(string path) =>
    Convert.FromBase64String(RemoveWhitespace(File.ReadAllText(path)));

static string RemoveWhitespace(string text) =>
    string.Concat(text.Where(character => !char.IsWhiteSpace(character)));

// Runs a verification stage, reporting native failures like the C demo does:
// the message on stderr and exit code 1.
static SnpAttestationReport VerifySnpAttestation(
    byte[] report, string arkPem, string askPem, string vcekPem)
{
    try
    {
        return AttestationVerifier.VerifySnpAttestation(report, arkPem, askPem, vcekPem);
    }
    catch (VerifyException error)
    {
        Console.Error.WriteLine($"verify attestation: {error.Message}");
        Environment.Exit(1);
        throw;
    }
}

static CborValue VerifyUvmEndorsement(byte[] uvmEndorsement, string trustedDidX509)
{
    try
    {
        return AttestationVerifier.VerifyUvmEndorsement(uvmEndorsement, trustedDidX509);
    }
    catch (VerifyException error)
    {
        Console.Error.WriteLine(
            $"verify UVM endorsement (code {(int)error.Code}): {error.Message}");
        Environment.Exit(1);
        throw;
    }
}

static byte[] VerifyCaciAttestation(
    SnpAttestationReport attestation,
    IEnumerable<(uint Cpuid, ReadOnlyMemory<byte> Tcb)> minimumTcb,
    IEnumerable<ReadOnlyMemory<byte>> trustedPolicies,
    CborValue uvm,
    string uvmFeed,
    ulong minimumSvn)
{
    try
    {
        return AttestationVerifier.VerifyCaciAttestation(
            attestation, minimumTcb, trustedPolicies, uvm, uvmFeed, minimumSvn);
    }
    catch (VerifyException error)
    {
        Console.Error.WriteLine(
            $"verify CACI attestation (code {(int)error.Code}): {error.Message}");
        Environment.Exit(1);
        throw;
    }
}

// Prints the UVM endorsement's content type and feed, read from the verified
// COSE_Sign1 protected header. Every navigation step owns a native handle.
static void PrintUvmEndorsement(CborValue uvmEndorsement)
{
    using CoseSign1 sign1 = uvmEndorsement.AsCoseSign1();
    using CborValue protectedHeader = sign1.GetProtectedHeader();
    using CborValue contentType = protectedHeader.MapAt(CoseHeaderContentType);
    using CborValue feed = protectedHeader.MapAt("feed");
    Console.WriteLine($"  content_type: {contentType.GetTextString()}");
    Console.WriteLine($"  feed: {feed.GetTextString()}");
}

static void PrintReportField(string name, byte[] value)
{
    Console.WriteLine($"  {name}");
    PrintHexLines(value, indent: 4);
}

// Prints bytes as lowercase hex, 16 bytes per line, each line indented.
static void PrintHexLines(byte[] data, int indent)
{
    string padding = new(' ', indent);
    for (int offset = 0; offset < data.Length; offset += 16)
    {
        int lineLength = Math.Min(16, data.Length - offset);
        Console.Write(padding);
        Console.WriteLine(Convert.ToHexString(data, offset, lineLength).ToLowerInvariant());
    }
}
