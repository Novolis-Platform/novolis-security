using System.Text;

namespace Novolis.Security.Cryptography;

/// <summary>HKDF-SHA512 (RFC 5869) for deriving keyed material from a high-entropy secret.</summary>
public static class HkdfSha512
{
    /// <summary>Derives <paramref name="outputLength"/> bytes using SHA-512 HKDF.</summary>
    public static byte[] Derive(ReadOnlySpan<byte> ikm, int outputLength, ReadOnlySpan<byte> salt = default, ReadOnlySpan<byte> info = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(outputLength);
        var output = new byte[outputLength];
        System.Security.Cryptography.HKDF.DeriveKey(
            System.Security.Cryptography.HashAlgorithmName.SHA512,
            ikm,
            output,
            salt,
            info);
        return output;
    }
}
