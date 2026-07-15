// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace TeeAttestationVerification;

public sealed class CoseSign1 : IDisposable
{
    private readonly object _sync = new();
    private readonly CborLifetime _lifetime;
    private readonly IntPtr _pointer;
    private bool _disposed;

    internal CoseSign1(CborLifetime lifetime, IntPtr pointer)
    {
        if (pointer == IntPtr.Zero)
        {
            throw new InvalidOperationException("Native COSE validation returned a null value.");
        }

        lifetime.AddReference();
        _lifetime = lifetime;
        _pointer = pointer;
    }

    ~CoseSign1()
    {
        DisposeCore();
    }

    public byte[] Protected()
    {
        using CborValue sign1 = AsCborValue();
        using CborValue value = sign1.ArrayAt(0);
        return value.Bytes();
    }

    public CborValue Unprotected()
    {
        using CborValue sign1 = AsCborValue();
        return sign1.ArrayAt(1);
    }

    public byte[] Payload()
    {
        using CborValue sign1 = AsCborValue();
        using CborValue value = sign1.ArrayAt(2);
        return value.Bytes();
    }

    public byte[] Signature()
    {
        using CborValue sign1 = AsCborValue();
        using CborValue value = sign1.ArrayAt(3);
        return value.Bytes();
    }

    public CborValue ProtectedHeader() => CborValue.FromBytes(Protected());

    public Task VerifyEmbeddedAsync(
        ReadOnlyMemory<byte> spkiDer,
        int coseAlgorithm)
    {
        return NativeResult.Complete(() =>
        {
            byte[] key = NativeResult.Snapshot(spkiDer, nameof(spkiDer));
            using CborNativeLease sign1 = AcquireNative();
            unsafe
            {
                fixed (byte* keyPointer = key)
                {
                    IntPtr error = NativeMethods.VerifyCoseSign1Embedded(
                        sign1.Pointer,
                        (IntPtr)keyPointer,
                        (nuint)key.Length,
                        coseAlgorithm);
                    NativeResult.ThrowIfError(error);
                }
            }
        });
    }

    public Task VerifyDetachedAsync(
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> spkiDer,
        int coseAlgorithm)
    {
        return NativeResult.Complete(() =>
        {
            byte[] payloadSnapshot = NativeResult.Snapshot(payload, nameof(payload));
            byte[] key = NativeResult.Snapshot(spkiDer, nameof(spkiDer));
            using CborNativeLease sign1 = AcquireNative();
            unsafe
            {
                fixed (byte* payloadPointer = payloadSnapshot)
                fixed (byte* keyPointer = key)
                {
                    IntPtr error = NativeMethods.VerifyCoseSign1Detached(
                        sign1.Pointer,
                        (IntPtr)payloadPointer,
                        (nuint)payloadSnapshot.Length,
                        (IntPtr)keyPointer,
                        (nuint)key.Length,
                        coseAlgorithm);
                    NativeResult.ThrowIfError(error);
                }
            }
        });
    }

    public void Dispose()
    {
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    private void DisposeCore()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _lifetime.ReleaseReference();
        }
    }

    private CborValue AsCborValue()
    {
        using CborNativeLease lease = AcquireNative();
        return CborValue.CreateBorrowed(_lifetime, lease.Pointer);
    }

    private CborNativeLease AcquireNative()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return new CborNativeLease(_lifetime, _pointer);
        }
    }
}
