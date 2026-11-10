using System.Security.Cryptography;
using System.Text;

namespace Novolis.Security.Authentication.Enrollment;

/// <summary>
/// Creates opaque enrollment references, one-time tokens, storage hashes, temporary credentials,
/// and product invite links. Delivery (UI copy, email, SMS) stays in the host.
/// </summary>
public sealed class EnrollmentTokenMint
{
    private readonly EnrollmentTokenOptions options;

    /// <summary>Initializes minting with host options.</summary>
    public EnrollmentTokenMint(EnrollmentTokenOptions options)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>Creates an opaque reference that contains no usable credential material.</summary>
    public string CreateReference() => Guid.CreateVersion7().ToString("N");

    /// <summary>Derives the one-time token that is shown or sent only to the enrollment recipient.</summary>
    public string CreateToken(string enrollmentReference) =>
        Base64Url(Compute(options.TokenPurpose, enrollmentReference));

    /// <summary>Hashes a received token for an indexed, non-reversible storage lookup.</summary>
    public string HashToken(string token) =>
        Convert.ToHexString(Compute(options.TokenHashPurpose, token)).ToLowerInvariant();

    /// <summary>Derives the current temporary credential only when completing enrollment.</summary>
    public string CreateTemporaryPassword(string enrollmentReference) =>
        $"{options.TemporaryPasswordPrefix}{Base64Url(Compute(options.TemporaryPasswordPurpose, enrollmentReference))}";

    /// <summary>
    /// Builds an enrollment URL at send or display time so the raw token need not be written to an outbox.
    /// </summary>
    public string CreateLink(string publicOrigin, string enrollmentReference)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(publicOrigin);
        var origin = publicOrigin.TrimEnd('/');
        var path = (options.LinkPath ?? "invite").Trim().Trim('/');
        var query = Uri.EscapeDataString(options.TokenQueryName ?? "token");
        var token = Uri.EscapeDataString(CreateToken(enrollmentReference));
        return $"{origin}/{path}?{query}={token}";
    }

    private byte[] Compute(string purpose, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var pepper = ResolvePepper();
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(pepper));
        return hmac.ComputeHash(Encoding.UTF8.GetBytes($"{purpose}\u001f{value}"));
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
            "EnrollmentTokenOptions.Pepper must be supplied outside Development.");
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
