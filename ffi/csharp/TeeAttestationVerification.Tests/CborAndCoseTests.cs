// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using System.Runtime.CompilerServices;

namespace TeeAttestationVerification.Tests;

public sealed class CborAndCoseTests
{
    private static readonly byte[] ProtectedHeader = [0xa1, 0x01, 0x26];
    private static readonly byte[] Payload = Encoding.UTF8.GetBytes("verification-only COSE vector");
    private static readonly byte[] Spki =
    [
        48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61,
        3, 1, 7, 3, 66, 0, 4, 201, 171, 117, 35, 159, 13, 22, 69, 184, 252, 18, 119,
        177, 246, 18, 133, 248, 151, 60, 164, 201, 112, 233, 4, 224, 54, 241, 53, 11,
        85, 3, 249, 180, 113, 248, 87, 244, 106, 253, 83, 32, 139, 158, 31, 51, 72,
        167, 32, 114, 51, 92, 109, 60, 158, 23, 216, 2, 11, 126, 11, 242, 186, 211,
        205,
    ];
    private static readonly byte[] Signature =
    [
        90, 37, 149, 163, 211, 129, 174, 167, 177, 116, 232, 19, 137, 13, 86, 18, 47,
        248, 221, 245, 81, 132, 222, 25, 6, 230, 131, 70, 41, 27, 154, 74, 57, 92,
        210, 184, 112, 104, 224, 64, 234, 0, 184, 153, 253, 249, 148, 125, 58, 93,
        103, 128, 147, 144, 252, 13, 252, 91, 233, 88, 189, 169, 103, 151,
    ];

    [Fact]
    public void CborScalarContainerTagAndMapMembersCallNativeAbi()
    {
        using CborValue integer = CborValue.FromBytes(new byte[] { 0x01 });
        Assert.Equal(CborKind.Int, integer.Kind);
        Assert.Equal(1, integer.Int());
        Assert.Equal(new byte[] { 0x01 }, integer.ToBytes());
        VerifyException typeError = Assert.Throws<VerifyException>(() => integer.Text());
        Assert.Equal(ErrorCode.CoseUnexpectedType, typeError.Code);

        using CborValue simple = CborValue.FromBytes(new byte[] { 0xf6 });
        Assert.Equal(CborKind.Simple, simple.Kind);
        Assert.Equal(22, simple.Simple());

        using CborValue bytes = CborValue.FromBytes(new byte[] { 0x43, 1, 2, 3 });
        Assert.Equal(CborKind.Bytes, bytes.Kind);
        Assert.Equal(new byte[] { 1, 2, 3 }, bytes.Bytes());

        using CborValue text = CborValue.FromBytes(new byte[] { 0x62, 0x68, 0x69 });
        Assert.Equal(CborKind.Text, text.Kind);
        Assert.Equal("hi", text.Text());

        using CborValue array = CborValue.FromBytes(new byte[] { 0x82, 0x01, 0x61, 0x61 });
        Assert.Equal(CborKind.Array, array.Kind);
        Assert.Equal(2, array.Length);
        using CborValue first = array.ArrayAt(0);
        using CborValue second = array.ArrayAt(1);
        Assert.Equal(1, first.Int());
        Assert.Equal("a", second.Text());

        using CborValue map = CborValue.FromBytes(
            new byte[] { 0xa3, 0x01, 0x63, (byte)'o', (byte)'n', (byte)'e',
                0x61, (byte)'k', 0x18, 0x2a, 0x41, 0xaa, 0xf5 });
        Assert.Equal(CborKind.Map, map.Kind);
        Assert.Equal(3, map.Length);
        using CborValue one = map.MapAt(1L);
        using CborValue fortyTwo = map.MapAt("k");
        using CborValue key = CborValue.FromBytes(new byte[] { 0x41, 0xaa });
        using CborValue trueValue = map.MapAt(key);
        Assert.Equal("one", one.Text());
        Assert.Equal(42, fortyTwo.Int());
        Assert.Equal(21, trueValue.Simple());
        Assert.True(map.MapHas(1L));
        Assert.False(map.MapHas(2L));
        Assert.True(map.MapHas("k"));
        Assert.False(map.MapHas("missing"));
        Assert.False(map.MapHas(""));
        Assert.True(map.MapHas(key));

        KeyValuePair<CborValue, CborValue> entry = map.MapEntryAt(0);
        using (entry.Key)
        using (entry.Value)
        {
            Assert.Equal(1, entry.Key.Int());
            Assert.Equal("one", entry.Value.Text());
        }
        using CborValue mapKey = map.MapKeyAt(1);
        using CborValue mapValue = map.MapValueAt(1);
        Assert.Equal("k", mapKey.Text());
        Assert.Equal(42, mapValue.Int());

        using CborValue tagged = CborValue.FromBytes(new byte[] { 0xc1, 0x18, 0x2a });
        Assert.Equal(CborKind.Tagged, tagged.Kind);
        Assert.Equal(1ul, tagged.Tag());
        using CborValue taggedPayload = tagged.TaggedPayload();
        Assert.Equal(42, taggedPayload.Int());

        Assert.Throws<VerifyException>(() => CborValue.FromBytes(ReadOnlyMemory<byte>.Empty));
    }

    [Fact]
    public void BorrowedChildrenRetainOwnedRootAndCopyBorrowedBytes()
    {
        CborValue root = CborValue.FromBytes(new byte[] { 0x81, 0x82, 0x43, 1, 2, 3, 0x01 });
        CborValue child = root.ArrayAt(0);
        root.Dispose();
        using CborValue grandchild = child.ArrayAt(0);
        byte[] copied = grandchild.Bytes();
        child.Dispose();

        Assert.Equal(new byte[] { 1, 2, 3 }, copied);
        Assert.Equal(new byte[] { 1, 2, 3 }, grandchild.Bytes());
        grandchild.Dispose();
        Assert.Throws<ObjectDisposedException>(() => grandchild.Bytes());
    }

    [Fact]
    public void AbandonedBorrowedCborValueReleasesDisposedOwnedRoot()
    {
        CborValue root = CborValue.FromBytes(new byte[] { 0x81, 0x01 });
        ManualResetEventSlim released = root.Lifetime.TrackReleaseForTest();
        WeakReference borrower = AbandonCborBorrower(root);

        root.Dispose();
        Assert.False(released.IsSet);

        Collect(borrower);

        Assert.True(released.IsSet);
        GC.KeepAlive(root);
    }

    [Fact]
    public void AbandonedCoseSign1ReleasesDisposedOwnedRoot()
    {
        CborValue root = CborValue.FromBytes(BuildSign1(embeddedPayload: true));
        ManualResetEventSlim released = root.Lifetime.TrackReleaseForTest();
        WeakReference borrower = AbandonCoseBorrower(root);

        root.Dispose();
        Assert.False(released.IsSet);

        Collect(borrower);

        Assert.True(released.IsSet);
        GC.KeepAlive(root);
    }

    [Fact]
    public async Task CoseSign1AccessorsAndBothVerificationModesCallNativeAbi()
    {
        CborValue embeddedRoot = CborValue.FromBytes(BuildSign1(embeddedPayload: true));
        CoseSign1 embedded = embeddedRoot.AsCoseSign1();
        embeddedRoot.Dispose();

        Assert.Equal(ProtectedHeader, embedded.Protected());
        using CborValue protectedHeader = embedded.ProtectedHeader();
        using CborValue algorithm = protectedHeader.MapAt(1L);
        Assert.Equal(-7, algorithm.Int());
        using CborValue unprotected = embedded.Unprotected();
        Assert.Equal(CborKind.Map, unprotected.Kind);
        Assert.Equal(Payload, embedded.Payload());
        Assert.Equal(Signature, embedded.Signature());
        Task embeddedVerification = embedded.VerifyEmbeddedAsync(Spki, -7);
        Assert.True(embeddedVerification.IsCompleted);
        await embeddedVerification;
        VerifyException emptyKey = await Assert.ThrowsAsync<VerifyException>(
            () => embedded.VerifyEmbeddedAsync(ReadOnlyMemory<byte>.Empty, -7));
        Assert.Equal(ErrorCode.InvalidArgument, emptyKey.Code);

        byte[] tampered = BuildSign1(embeddedPayload: true);
        tampered[^1] ^= 0xff;
        using CborValue tamperedRoot = CborValue.FromBytes(tampered);
        using CoseSign1 tamperedSign1 = tamperedRoot.AsCoseSign1();
        VerifyException verificationError = await Assert.ThrowsAsync<VerifyException>(
            () => tamperedSign1.VerifyEmbeddedAsync(Spki, -7));
        Assert.Equal(ErrorCode.CoseVerification, verificationError.Code);

        using CborValue detachedRoot = CborValue.FromBytes(BuildSign1(embeddedPayload: false));
        using CoseSign1 detached = detachedRoot.AsCoseSign1();
        Task detachedVerification = detached.VerifyDetachedAsync(Payload, Spki, -7);
        Assert.True(detachedVerification.IsCompleted);
        await detachedVerification;

        VerifyException wrongMode = await Assert.ThrowsAsync<VerifyException>(
            () => embedded.VerifyDetachedAsync(Payload, Spki, -7));
        Assert.Equal(ErrorCode.CoseUnexpectedType, wrongMode.Code);

        embedded.Dispose();
        Assert.Throws<ObjectDisposedException>(() => embedded.Signature());
    }

    private static byte[] BuildSign1(bool embeddedPayload)
    {
        List<byte> bytes = [0xd2, 0x84];
        PutByteString(bytes, ProtectedHeader);
        bytes.Add(0xa0);
        if (embeddedPayload)
        {
            PutByteString(bytes, Payload);
        }
        else
        {
            bytes.Add(0xf6);
        }

        PutByteString(bytes, Signature);
        return bytes.ToArray();
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference AbandonCborBorrower(CborValue root) =>
        new(root.ArrayAt(0));

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference AbandonCoseBorrower(CborValue root) =>
        new(root.AsCoseSign1());

    private static void Collect(WeakReference reference)
    {
        for (int attempt = 0; attempt < 10 && reference.IsAlive; attempt++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }

        Assert.False(reference.IsAlive);
    }

    private static void PutByteString(List<byte> destination, byte[] value)
    {
        if (value.Length < 24)
        {
            destination.Add((byte)(0x40 | value.Length));
        }
        else
        {
            destination.Add(0x58);
            destination.Add((byte)value.Length);
        }

        destination.AddRange(value);
    }
}
