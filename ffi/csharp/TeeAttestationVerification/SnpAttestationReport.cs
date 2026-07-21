// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace TeeAttestationVerification;

public sealed class SnpAttestationReport : IDisposable
{
    private readonly object _sync = new();
    private SafeSnpReportHandle? _handle;

    internal SnpAttestationReport(IntPtr handle)
    {
        if (handle == IntPtr.Zero)
        {
            throw new InvalidOperationException("Native verification returned a null report.");
        }

        _handle = new SafeSnpReportHandle(handle);
    }

    public uint Version => Get(NativeMethods.SnpVersion);
    public uint GuestSvn => Get(NativeMethods.SnpGuestSvn);
    public ulong Policy => Get(NativeMethods.SnpPolicy);
    public byte PolicyAbiMinor => Get(NativeMethods.SnpPolicyAbiMinor);
    public byte PolicyAbiMajor => Get(NativeMethods.SnpPolicyAbiMajor);
    public bool PolicySmt => Get(NativeMethods.SnpPolicySmt) != 0;
    public bool PolicyMigrateMa => Get(NativeMethods.SnpPolicyMigrateMa) != 0;
    public bool PolicyDebug => Get(NativeMethods.SnpPolicyDebug) != 0;
    public bool PolicySingleSocket => Get(NativeMethods.SnpPolicySingleSocket) != 0;
    public bool PolicyCxlAllow => Get(NativeMethods.SnpPolicyCxlAllow) != 0;
    public bool PolicyMemAes256Xts => Get(NativeMethods.SnpPolicyMemAes256Xts) != 0;
    public bool PolicyRaplDis => Get(NativeMethods.SnpPolicyRaplDis) != 0;
    public bool PolicyCiphertextHidingDram =>
        Get(NativeMethods.SnpPolicyCiphertextHidingDram) != 0;
    public bool PolicyPageSwapDisable => Get(NativeMethods.SnpPolicyPageSwapDisable) != 0;
    public uint Vmpl => Get(NativeMethods.SnpVmpl);
    public uint SignatureAlgorithm => Get(NativeMethods.SnpSignatureAlgorithm);
    public ulong PlatformInfo => Get(NativeMethods.SnpPlatformInfo);
    public uint Flags => Get(NativeMethods.SnpFlags);
    public bool FlagsAuthorKeyEnabled => Get(NativeMethods.SnpFlagsAuthorKeyEnabled) != 0;
    public bool FlagsMaskChipKey => Get(NativeMethods.SnpFlagsMaskChipKey) != 0;
    public byte FlagsSigningKey => Get(NativeMethods.SnpFlagsSigningKey);
    public byte CpuidFamilyId => Get(NativeMethods.SnpCpuidFamilyId);
    public byte CpuidModelId => Get(NativeMethods.SnpCpuidModelId);
    public byte CpuidStepping => Get(NativeMethods.SnpCpuidStepping);
    public byte CurrentBuild => Get(NativeMethods.SnpCurrentBuild);
    public byte CurrentMinor => Get(NativeMethods.SnpCurrentMinor);
    public byte CurrentMajor => Get(NativeMethods.SnpCurrentMajor);
    public byte CommittedBuild => Get(NativeMethods.SnpCommittedBuild);
    public byte CommittedMinor => Get(NativeMethods.SnpCommittedMinor);
    public byte CommittedMajor => Get(NativeMethods.SnpCommittedMajor);
    public byte[] FamilyId => GetBytes(NativeMethods.SnpFamilyId);
    public byte[] ImageId => GetBytes(NativeMethods.SnpImageId);
    public byte[] PlatformVersion => GetBytes(NativeMethods.SnpPlatformVersion);
    public byte[] ReportData => GetBytes(NativeMethods.SnpReportData);
    public byte[] Measurement => GetBytes(NativeMethods.SnpMeasurement);
    public byte[] HostData => GetBytes(NativeMethods.SnpHostData);
    public byte[] IdKeyDigest => GetBytes(NativeMethods.SnpIdKeyDigest);
    public byte[] AuthorKeyDigest => GetBytes(NativeMethods.SnpAuthorKeyDigest);
    public byte[] ReportId => GetBytes(NativeMethods.SnpReportId);
    public byte[] ReportIdMa => GetBytes(NativeMethods.SnpReportIdMa);
    public byte[] ReportedTcb => GetBytes(NativeMethods.SnpReportedTcb);
    public byte[] ChipId => GetBytes(NativeMethods.SnpChipId);
    public byte[] CommittedTcb => GetBytes(NativeMethods.SnpCommittedTcb);
    public byte[] LaunchTcb => GetBytes(NativeMethods.SnpLaunchTcb);
    public byte[] SignatureR => GetBytes(NativeMethods.SnpSignatureR);
    public byte[] SignatureS => GetBytes(NativeMethods.SnpSignatureS);

    public void Dispose()
    {
        SafeSnpReportHandle? handle;
        lock (_sync)
        {
            handle = _handle;
            _handle = null;
        }

        handle?.Dispose();
    }

    internal SafeHandleLease AcquireHandle()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_handle is null, this);
            return new SafeHandleLease(_handle);
        }
    }

    private T Get<T>(Func<IntPtr, T> accessor)
    {
        using SafeHandleLease lease = AcquireHandle();
        return accessor(lease.Pointer);
    }

    private byte[] GetBytes(BytesAccessor accessor)
    {
        using SafeHandleLease lease = AcquireHandle();
        accessor(lease.Pointer, out IntPtr data, out nuint length);
        return NativeResult.CopyBytes(data, length);
    }

    private delegate void BytesAccessor(IntPtr report, out IntPtr data, out nuint length);
}
