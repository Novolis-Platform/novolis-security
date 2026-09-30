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
