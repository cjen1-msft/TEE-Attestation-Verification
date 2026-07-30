// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace TeeAttestationVerification;

/// <summary>
/// An immutable, native-ready collection of trusted CACI execution-policy
/// SHA-256 digests.
/// </summary>
public sealed class CaciPolicyDigests
{
    private const int DigestLength = 32;
    private readonly byte[] _bytes;

    /// <summary>Creates a digest collection by validating and copying each input.</summary>
    /// <param name="digests">One or more 32-byte SHA-256 digests.</param>
    /// <exception cref="ArgumentNullException"><paramref name="digests"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// The collection is empty or an element is not 32 bytes.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">The collection exceeds the native input limit.</exception>
    public CaciPolicyDigests(IEnumerable<ReadOnlyMemory<byte>> digests)
    {
        ArgumentNullException.ThrowIfNull(digests);

        ReadOnlyMemory<byte>[] snapshot = digests.ToArray();
        if (snapshot.Length == 0)
        {
            throw new ArgumentException(
                "At least one CACI policy digest is required.",
                nameof(digests));
        }
        if (snapshot.Length > NativeInput.MaximumInputLength / DigestLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(digests),
                "CACI policy digests exceed the maximum input size.");
        }

        _bytes = new byte[checked(snapshot.Length * DigestLength)];
        for (int index = 0; index < snapshot.Length; index++)
        {
            ReadOnlyMemory<byte> digest = snapshot[index];
            if (digest.Length != DigestLength)
            {
                throw new ArgumentException(
                    $"CACI policy digest at index {index} must be {DigestLength} bytes, got {digest.Length}.",
                    nameof(digests));
            }

            digest.Span.CopyTo(
                _bytes.AsSpan(index * DigestLength, DigestLength));
        }
    }

    /// <summary>Gets the number of trusted policy digests.</summary>
    public int Count => _bytes.Length / DigestLength;

    internal ReadOnlySpan<byte> Bytes => _bytes;
}
