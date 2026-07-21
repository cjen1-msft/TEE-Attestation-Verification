// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace TeeAttestationVerification;

public sealed class CborValue : IDisposable
{
    private readonly object _sync = new();
    private readonly CborLifetime _lifetime;
    private readonly IntPtr _pointer;
    private bool _disposed;

    private CborValue(CborLifetime lifetime, IntPtr pointer, bool addReference)
    {
        if (pointer == IntPtr.Zero)
        {
            throw new InvalidOperationException("Native CBOR operation returned a null value.");
        }

        if (addReference)
        {
            lifetime.AddReference();
        }

        _lifetime = lifetime;
        _pointer = pointer;
    }

    ~CborValue()
    {
        DisposeCore();
    }

    public CborKind Kind
    {
        get
        {
            using CborNativeLease lease = AcquireNative();
            return (CborKind)NativeMethods.CborKind(lease.Pointer);
        }
    }

    public int Length
    {
        get
        {
            using CborNativeLease lease = AcquireNative();
            IntPtr error = NativeMethods.CborLength(lease.Pointer, out nuint length);
            NativeResult.ThrowIfError(error);
            return NativeResult.ToManagedLength(length);
        }
    }

    public static unsafe CborValue FromBytes(ReadOnlyMemory<byte> bytes)
    {
        byte[] snapshot = NativeResult.Snapshot(bytes, nameof(bytes));
        fixed (byte* bytesPointer = snapshot)
        {
            IntPtr error = NativeMethods.CborFromBytes(
                (IntPtr)bytesPointer, (nuint)snapshot.Length, out IntPtr value);
            NativeResult.ThrowIfError(error);
            return FromOwnedHandle(value);
        }
    }

    public byte[] ToBytes()
    {
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.CborToBytes(lease.Pointer, out IntPtr bytes);
        NativeResult.ThrowIfError(error);
        if (bytes == IntPtr.Zero)
        {
            throw new InvalidOperationException("Native CBOR serialization returned a null buffer.");
        }

        return NativeResult.CopyOwnedBytes(bytes);
    }

    public long Int()
    {
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.CborInt(lease.Pointer, out long value);
        NativeResult.ThrowIfError(error);
        return value;
    }

    public byte Simple()
    {
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.CborSimple(lease.Pointer, out byte value);
        NativeResult.ThrowIfError(error);
        return value;
    }

    public byte[] Bytes()
    {
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.CborBytes(
            lease.Pointer, out IntPtr data, out nuint length);
        NativeResult.ThrowIfError(error);
        return NativeResult.CopyBytes(data, length);
    }

    public string Text()
    {
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.CborText(
            lease.Pointer, out IntPtr text, out nuint length);
        NativeResult.ThrowIfError(error);
        return NativeResult.CopyUtf8(text, length);
    }

    public ulong Tag()
    {
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.CborTag(lease.Pointer, out ulong tag);
        NativeResult.ThrowIfError(error);
        return tag;
    }

    public CborValue TaggedPayload()
    {
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.CborTaggedPayload(lease.Pointer, out IntPtr payload);
        NativeResult.ThrowIfError(error);
        return CreateBorrowed(_lifetime, payload);
    }

    public CborValue ArrayAt(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.CborArrayAt(
            lease.Pointer, (nuint)index, out IntPtr child);
        NativeResult.ThrowIfError(error);
        return CreateBorrowed(_lifetime, child);
    }

    public CborValue MapAt(long key)
    {
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.CborMapAtInt(lease.Pointer, key, out IntPtr child);
        NativeResult.ThrowIfError(error);
        return CreateBorrowed(_lifetime, child);
    }

    public unsafe CborValue MapAt(string key)
    {
        byte[] utf8 = NativeResult.Utf8(key, nameof(key));
        using CborNativeLease lease = AcquireNative();
        fixed (byte* keyPointer = utf8)
        {
            IntPtr error = NativeMethods.CborMapAtText(
                lease.Pointer, (IntPtr)keyPointer, (nuint)utf8.Length, out IntPtr child);
            NativeResult.ThrowIfError(error);
            return CreateBorrowed(_lifetime, child);
        }
    }

    public CborValue MapAt(CborValue key)
    {
        ArgumentNullException.ThrowIfNull(key);
        using CborNativeLease valueLease = AcquireNative();
        using CborNativeLease keyLease = key.AcquireNative();
        IntPtr error = NativeMethods.CborMapAt(
            valueLease.Pointer, keyLease.Pointer, out IntPtr child);
        NativeResult.ThrowIfError(error);
        return CreateBorrowed(_lifetime, child);
    }

    public bool MapHas(long key)
    {
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.CborMapHasInt(lease.Pointer, key, out byte result);
        NativeResult.ThrowIfError(error);
        return result != 0;
    }

    public unsafe bool MapHas(string key)
    {
        byte[] utf8 = NativeResult.Utf8(key, nameof(key));
        using CborNativeLease lease = AcquireNative();
        fixed (byte* keyPointer = utf8)
        {
            IntPtr error = NativeMethods.CborMapHasText(
                lease.Pointer, (IntPtr)keyPointer, (nuint)utf8.Length, out byte result);
            NativeResult.ThrowIfError(error);
            return result != 0;
        }
    }

    public bool MapHas(CborValue key)
    {
        ArgumentNullException.ThrowIfNull(key);
        using CborNativeLease valueLease = AcquireNative();
        using CborNativeLease keyLease = key.AcquireNative();
        IntPtr error = NativeMethods.CborMapHas(
            valueLease.Pointer, keyLease.Pointer, out byte result);
        NativeResult.ThrowIfError(error);
        return result != 0;
    }

    public KeyValuePair<CborValue, CborValue> MapEntryAt(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.CborMapEntryAt(
            lease.Pointer, (nuint)index, out IntPtr key, out IntPtr value);
        NativeResult.ThrowIfError(error);
        return new(
            CreateBorrowed(_lifetime, key),
            CreateBorrowed(_lifetime, value));
    }

    public CborValue MapKeyAt(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.CborMapKeyAt(
            lease.Pointer, (nuint)index, out IntPtr key);
        NativeResult.ThrowIfError(error);
        return CreateBorrowed(_lifetime, key);
    }

    public CborValue MapValueAt(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.CborMapValueAt(
            lease.Pointer, (nuint)index, out IntPtr value);
        NativeResult.ThrowIfError(error);
        return CreateBorrowed(_lifetime, value);
    }

    public CoseSign1 AsCoseSign1()
    {
        using CborNativeLease lease = AcquireNative();
        IntPtr error = NativeMethods.ValidateCoseSign1(lease.Pointer, out IntPtr sign1);
        NativeResult.ThrowIfError(error);
        return new CoseSign1(_lifetime, sign1);
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

    internal static CborValue FromOwnedHandle(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero)
        {
            throw new InvalidOperationException("Native operation returned a null CBOR handle.");
        }

        SafeCborValueHandle handle = new(pointer);
        return new CborValue(new CborLifetime(handle), pointer, addReference: false);
    }

    internal static CborValue CreateBorrowed(CborLifetime lifetime, IntPtr pointer) =>
        new(lifetime, pointer, addReference: true);

    internal CborNativeLease AcquireNative()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return new CborNativeLease(_lifetime, _pointer);
        }
    }

    internal CborLifetime Lifetime => _lifetime;
}
