using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Novolis.Security.PasswordHashing;

public class PasswordHasher(IOptions<PasswordHasherOptions> options)
{
    public string HashPassword(string password)
    {
        var salt = GenerateSalt();
        var hash = HashPassword(password, salt);
        var hashBytes = new byte[options.Value.SaltSize + options.Value.KeySize];
        salt.CopyTo(hashBytes);
        hash.CopyTo(hashBytes.AsSpan(options.Value.SaltSize));
        return Convert.ToBase64String(hashBytes);
    }

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
