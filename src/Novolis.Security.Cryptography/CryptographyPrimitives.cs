using System.Text;

namespace Novolis.Security.Cryptography;

/// <summary>CSPRNG helpers. Always uses <see cref="System.Security.Cryptography.RandomNumberGenerator"/>.</summary>
public static class SecureRandom
{
    /// <summary>Fills <paramref name="buffer"/> with cryptographically strong random bytes.</summary>
    public static void Fill(Span<byte> buffer) => System.Security.Cryptography.RandomNumberGenerator.Fill(buffer);

    /// <summary>Returns <paramref name="count"/> random bytes.</summary>
    public static byte[] GetBytes(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);
        return System.Security.Cryptography.RandomNumberGenerator.GetBytes(count);
    }

    /// <summary>Returns a cryptographically strong integer in <c>[0, toExclusive)</c>.</summary>
    public static int GetInt32(int toExclusive) =>
        System.Security.Cryptography.RandomNumberGenerator.GetInt32(toExclusive);

    /// <summary>Returns a cryptographically strong integer in <c>[fromInclusive, toExclusive)</c>.</summary>
    public static int GetInt32(int fromInclusive, int toExclusive) =>
        System.Security.Cryptography.RandomNumberGenerator.GetInt32(fromInclusive, toExclusive);
}

/// <summary>Fixed-time comparisons that do not short-circuit on the first differing byte.</summary>
public static class ConstantTime
{
    /// <summary>Compares two spans. Different lengths return false without throwing.</summary>
    public static bool Equals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(left, right);

    /// <summary>UTF-8 encodes both strings and compares in fixed time. Nulls are not equal.</summary>
    public static bool EqualsUtf8(string? left, string? right)
    {
        if (ReferenceEquals(left, right))
            return true;
        if (left is null || right is null)
            return false;

        var leftCount = Encoding.UTF8.GetByteCount(left);
        var rightCount = Encoding.UTF8.GetByteCount(right);
        if (leftCount != rightCount)
            return false;
        if (leftCount == 0)
            return true;

        if (leftCount <= 256)
        {
            Span<byte> leftBuf = stackalloc byte[leftCount];
            Span<byte> rightBuf = stackalloc byte[rightCount];
            Encoding.UTF8.GetBytes(left, leftBuf);
            Encoding.UTF8.GetBytes(right, rightBuf);
            return Equals(leftBuf, rightBuf);
        }

        var leftArr = Encoding.UTF8.GetBytes(left);
        var rightArr = Encoding.UTF8.GetBytes(right);
        try
        {
            return Equals(leftArr, rightArr);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(leftArr);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(rightArr);
        }
    }
}

/// <summary>Overwrites secret buffers.</summary>
public static class SecureMemory
{
    /// <summary>Zeroes <paramref name="buffer"/>.</summary>
    public static void Zero(Span<byte> buffer) =>
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer);
}

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
