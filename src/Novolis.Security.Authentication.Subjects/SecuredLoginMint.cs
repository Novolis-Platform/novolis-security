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
    /// Owner-facing mask for a secured subject. The auth subject is a one-way hash;
    /// owners never see it — only <see cref="LoginDisplay.ObscuredLogin"/>.
    /// </summary>
    public static string ToPublicLogin(string? securedOrOpaqueSubject)
    {
        _ = securedOrOpaqueSubject;
        return LoginDisplay.ObscuredLogin;
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
