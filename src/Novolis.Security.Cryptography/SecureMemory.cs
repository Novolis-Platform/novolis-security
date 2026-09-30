using System.Text;

namespace Novolis.Security.Cryptography;

/// <summary>Overwrites secret buffers.</summary>
public static class SecureMemory
{
    /// <summary>Zeroes <paramref name="buffer"/>.</summary>
    public static void Zero(Span<byte> buffer) =>
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer);
}
