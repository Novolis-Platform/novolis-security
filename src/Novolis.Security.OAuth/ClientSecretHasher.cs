using System.Security.Cryptography;
using System.Text;
using Novolis.Security.Cryptography;

namespace Novolis.Security.OAuth;

/// <summary>Self-describing PBKDF2-SHA512 hashing for confidential OAuth client secrets.</summary>
public sealed class ClientSecretHasher
{
    const int DefaultIterations = 210_000;
    const int SaltSize = 16;
    const int HashSize = 32;

    /// <summary>Hashes a client secret without retaining the original value.</summary>
    public string Hash(string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        var salt = SecureRandom.GetBytes(SaltSize);
        var hash = Derive(secret, salt, DefaultIterations);
        return $"$novolis-client$pbkdf2-sha512${DefaultIterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    /// <summary>Verifies a self-describing client-secret hash in constant time.</summary>
    public bool Verify(string encoded, string secret)
    {
        if (string.IsNullOrEmpty(encoded) || string.IsNullOrEmpty(secret))
            return false;

        var parts = encoded.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 5
            || !string.Equals(parts[0], "novolis-client", StringComparison.Ordinal)
            || !string.Equals(parts[1], "pbkdf2-sha512", StringComparison.Ordinal)
            || !int.TryParse(parts[2], out var iterations)
            || iterations < 100_000
            || iterations > 2_000_000)
            return false;

        try
        {
            var salt = Convert.FromBase64String(parts[3]);
            var expected = Convert.FromBase64String(parts[4]);
            var actual = Derive(secret, salt, iterations, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    static byte[] Derive(
        string secret,
        byte[] salt,
        int iterations,
        int length = HashSize) =>
        Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(secret.Normalize(NormalizationForm.FormC)),
            salt,
            iterations,
            HashAlgorithmName.SHA512,
            length);
}
