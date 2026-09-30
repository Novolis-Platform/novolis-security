using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Novolis.Security.Cryptography;

namespace Novolis.Security.OAuth;

internal static class AuthorizationCodeFormat
{
    public const int SecretSize = 32;

    public static string Create(Guid id, out byte[] secret)
    {
        secret = SecureRandom.GetBytes(SecretSize);
        return $"{id:N}.{Base64UrlEncoder.Encode(secret)}";
    }

    public static bool TryParse(
        string? value,
        out Guid id,
        out byte[] secret)
    {
        id = default;
        secret = [];
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var dot = value.IndexOf('.');
        if (dot <= 0 || dot == value.Length - 1)
            return false;
        if (!Guid.TryParseExact(value[..dot], "N", out id))
            return false;

        try
        {
            secret = Base64UrlEncoder.DecodeBytes(value[(dot + 1)..]);
        }
        catch (FormatException)
        {
            return false;
        }

        return secret.Length == SecretSize;
    }

    public static string HashSecret(ReadOnlySpan<byte> secret) =>
        Convert.ToBase64String(SHA512.HashData(secret));
}
