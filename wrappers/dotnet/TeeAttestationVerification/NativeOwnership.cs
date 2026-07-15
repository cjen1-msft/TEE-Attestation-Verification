// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text;

namespace TeeAttestationVerification;

internal sealed class SafeErrorHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeErrorHandle(IntPtr handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.ErrorFree(handle);
        return true;
    }
}

internal sealed class SafeByteBufferHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeByteBufferHandle(IntPtr handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.ByteBufferFree(handle);
        return true;
    }
}

internal sealed class SafeSnpReportHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeSnpReportHandle(IntPtr handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.SnpReportFree(handle);
        return true;
    }
}

internal sealed class SafeCborValueHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeCborValueHandle(IntPtr handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.CborFree(handle);
        return true;
    }
}

internal sealed class SafeHandleLease : IDisposable
{
    private SafeHandle? _handle;

    internal SafeHandleLease(SafeHandle handle)
    {
        bool added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            Pointer = handle.DangerousGetHandle();
            _handle = handle;
        }
        catch
        {
            if (added)
            {
                handle.DangerousRelease();
            }

            throw;
        }
    }

    internal IntPtr Pointer { get; }

    public void Dispose()
    {
        SafeHandle? handle = Interlocked.Exchange(ref _handle, null);
        handle?.DangerousRelease();
    }
}

internal sealed class CborLifetime
{
    private readonly SafeCborValueHandle _handle;
    private ManualResetEventSlim? _releaseSignalForTest;
    private int _references = 1;

    internal CborLifetime(SafeCborValueHandle handle)
    {
        _handle = handle;
    }

    internal void AddReference()
    {
        while (true)
        {
            int current = Volatile.Read(ref _references);
            if (current == 0)
            {
                throw new ObjectDisposedException(nameof(CborValue));
            }

            if (Interlocked.CompareExchange(ref _references, current + 1, current) == current)
            {
                return;
            }
        }
    }

    internal void ReleaseReference()
    {
        if (Interlocked.Decrement(ref _references) == 0)
        {
            _handle.Dispose();
            Volatile.Read(ref _releaseSignalForTest)?.Set();
        }
    }

    internal ManualResetEventSlim TrackReleaseForTest()
    {
        ManualResetEventSlim? signal = Volatile.Read(ref _releaseSignalForTest);
        if (signal is not null)
        {
            return signal;
        }

        ManualResetEventSlim created = new();
        signal = Interlocked.CompareExchange(
            ref _releaseSignalForTest, created, comparand: null);
        if (signal is null)
        {
            return created;
        }

        created.Dispose();
        return signal;
    }
}

internal sealed class CborNativeLease : IDisposable
{
    private CborLifetime? _lifetime;

    internal CborNativeLease(CborLifetime lifetime, IntPtr pointer)
    {
        lifetime.AddReference();
        _lifetime = lifetime;
        Pointer = pointer;
    }

    internal IntPtr Pointer { get; }

    public void Dispose()
    {
        CborLifetime? lifetime = Interlocked.Exchange(ref _lifetime, null);
        lifetime?.ReleaseReference();
    }
}

internal static class NativeResult
{
    internal const int MaximumInputLength = 1024 * 1024 * 1024;

    internal static void ThrowIfError(IntPtr error)
    {
        if (error == IntPtr.Zero)
        {
            return;
        }

        using SafeErrorHandle handle = new(error);
        ErrorCode code = (ErrorCode)NativeMethods.ErrorCode(error);
        string message = Marshal.PtrToStringUTF8(NativeMethods.ErrorMessage(error))
            ?? "native verification failed without an error message";
        throw new VerifyException(code, message);
    }

    internal static byte[] CopyOwnedBytes(IntPtr buffer)
    {
        using SafeByteBufferHandle handle = new(buffer);
        return CopyBytes(
            NativeMethods.ByteBufferData(buffer),
            NativeMethods.ByteBufferLength(buffer));
    }

    internal static byte[] CopyBytes(IntPtr data, nuint length)
    {
        if (length > int.MaxValue)
        {
            throw new InvalidOperationException("Native buffer is too large for a managed array.");
        }

        int managedLength = checked((int)length);
        if (managedLength == 0)
        {
            return [];
        }

        if (data == IntPtr.Zero)
        {
            throw new InvalidOperationException("Native buffer pointer is null.");
        }

        byte[] result = new byte[managedLength];
        Marshal.Copy(data, result, 0, managedLength);
        return result;
    }

    internal static string CopyUtf8(IntPtr data, nuint length)
    {
        byte[] bytes = CopyBytes(data, length);
        return new UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true).GetString(bytes);
    }

    internal static byte[] Snapshot(ReadOnlyMemory<byte> input, string name)
    {
        ValidateLength(input.Length, name);
        return input.ToArray();
    }

    internal static byte[] Utf8(string input, string name)
    {
        ArgumentNullException.ThrowIfNull(input);
        int length = Encoding.UTF8.GetByteCount(input);
        ValidateLength(length, name);
        return Encoding.UTF8.GetBytes(input);
    }

    internal static int ToManagedLength(nuint length)
    {
        if (length > int.MaxValue)
        {
            throw new InvalidOperationException("Native length exceeds Int32.MaxValue.");
        }

        return checked((int)length);
    }

    internal static void ValidateLength(int length, string name)
    {
        if (length > MaximumInputLength)
        {
            throw new ArgumentOutOfRangeException(
                name,
                $"Input exceeds the {MaximumInputLength}-byte maximum.");
        }
    }

    internal static Task<T> Complete<T>(Func<T> operation)
    {
        try
        {
            return Task.FromResult(operation());
        }
        catch (Exception exception)
        {
            return Task.FromException<T>(exception);
        }
    }

    internal static Task Complete(Action operation)
    {
        try
        {
            operation();
            return Task.CompletedTask;
        }
        catch (Exception exception)
        {
            return Task.FromException(exception);
        }
    }
}
