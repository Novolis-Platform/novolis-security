using System.Security.Authentication;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Novolis.Security.Cryptography;

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
    
    private ReadOnlySpan<byte> HashPassword(string password, ReadOnlySpan<byte> salt)
    {
        using var bytes = new PasswordDeriveBytes(password, salt.ToArray(), HashAlgorithmType.Sha512.ToString().ToUpperInvariant(), options.Value.Iterations);
        return bytes.GetBytes(options.Value.KeySize);
    }

    private ReadOnlySpan<byte> GenerateSalt() => RandomNumberGenerator.GetBytes(options.Value.SaltSize);
}