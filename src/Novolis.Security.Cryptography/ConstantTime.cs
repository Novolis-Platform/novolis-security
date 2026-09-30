using System.Text;

namespace Novolis.Security.Cryptography;

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
