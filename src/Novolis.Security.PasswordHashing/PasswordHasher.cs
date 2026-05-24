using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Novolis.Security.PasswordHashing;

/// <summary>PBKDF2 password hasher with configurable salt and key size.</summary>
public class PasswordHasher(IOptions<PasswordHasherOptions> options)
{
    /// <summary>Hashes a password with a newly generated salt.</summary>
    /// <param name="password">Plain-text password.</param>
    /// <returns>Base64-encoded salt + hash bytes.</returns>
    public string HashPassword(string password)
    {
        var salt = GenerateSalt();
        var hash = HashPassword(password, salt);
        var hashBytes = new byte[options.Value.SaltSize + options.Value.KeySize];
        salt.CopyTo(hashBytes);
        hash.CopyTo(hashBytes.AsSpan(options.Value.SaltSize));
        return Convert.ToBase64String(hashBytes);
    }

    /// <summary>Verifies a password against a previously hashed value.</summary>
    /// <param name="hashedPassword">Base64 hash from the parameterless hash method.</param>
    /// <param name="password">Candidate plain-text password.</param>
    /// <returns>True when the password matches.</returns>
    public bool CompareHashedPassword(string hashedPassword, string password)
    {
        var hashBytes = Convert.FromBase64String(hashedPassword);
        var salt = hashBytes.AsSpan(0, options.Value.SaltSize);
        var hash = hashBytes.AsSpan(options.Value.SaltSize, options.Value.KeySize);
        var passwordHash = HashPassword(password, salt);
        return passwordHash.SequenceEqual(hash);
    }

    private byte[] HashPassword(string password, ReadOnlySpan<byte> salt) =>
        Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            options.Value.Iterations,
            HashAlgorithmName.SHA512,
            options.Value.KeySize);

    private byte[] GenerateSalt() => RandomNumberGenerator.GetBytes(options.Value.SaltSize);
}
