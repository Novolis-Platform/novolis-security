using System.Security.Cryptography;
using System.Text;

namespace Novolis.Security.Authentication.Subjects;

/// <summary>
/// Turns a sensitive identifier (such as a national id) into a stable auth subject.
/// The raw value is never part of the stored login; owners work with a separate display label.
/// </summary>
public sealed class SecuredLoginMint
{
    /// <summary>Prefix for secured login subjects.</summary>
    public const string Prefix = "sec:";

    private readonly SecuredLoginOptions options;

    /// <summary>Initializes minting with host pepper options.</summary>
    public SecuredLoginMint(SecuredLoginOptions options)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>Builds <c>sec:{scheme}:{hash}</c> for a normalized sensitive identifier.</summary>
    public string Create(string scheme, string normalizedValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        ArgumentException.ThrowIfNullOrWhiteSpace(normalizedValue);
        var pepper = ResolvePepper();
        var purpose = $"{options.Purpose}/{scheme.Trim().ToLowerInvariant()}";
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(pepper));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes($"{purpose}\u001f{normalizedValue}"));
        return $"{Prefix}{scheme.Trim().ToLowerInvariant()}:{Base64Url(hash)}";
    }

    /// <summary>Whether a stored login is a secured subject.</summary>
    public static bool IsSecured(string? login) =>
        !string.IsNullOrWhiteSpace(login) &&
        login.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Stable alphanumeric login shown to owners. Derived from a hash of the auth subject so
    /// scheme flavor and raw identifiers never appear in the product surface.
    /// </summary>
    public static string ToPublicLogin(string securedOrOpaqueSubject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(securedOrOpaqueSubject);
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(securedOrOpaqueSubject.Trim())))
            .ToLowerInvariant();
        return digest.Length <= 16 ? digest : digest[..16];
    }

    private string ResolvePepper()
    {
        if (!string.IsNullOrWhiteSpace(options.Pepper))
        {
            return options.Pepper;
        }

        if (options.AllowDevelopmentPepper &&
            !string.IsNullOrWhiteSpace(options.DevelopmentPepper))
        {
            return options.DevelopmentPepper;
        }

        throw new InvalidOperationException(
            "SecuredLoginOptions.Pepper must be supplied outside Development.");
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
