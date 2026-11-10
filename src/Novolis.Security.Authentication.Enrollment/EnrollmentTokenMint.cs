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
        CreateToken(enrollmentReference, ResolveCurrentPepper());

    /// <summary>Derives the recipient token for a specific pepper (re-issue after rotation).</summary>
    public string CreateToken(string enrollmentReference, string pepper)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pepper);
        return Base64Url(Compute(options.TokenPurpose, enrollmentReference, pepper));
    }

    /// <summary>Hashes a received token for an indexed, non-reversible storage lookup (current pepper).</summary>
    public string HashToken(string token) =>
        Convert.ToHexString(Compute(options.TokenHashPurpose, token, ResolveCurrentPepper()))
            .ToLowerInvariant();

    /// <summary>
    /// Current then previous pepper hashes so outstanding invites survive pepper rotation.
    /// </summary>
    public IReadOnlyList<string> HashTokenCandidates(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        var hashes = new List<string>();
        foreach (var pepper in EnumeratePeppers())
        {
            var hash = Convert.ToHexString(Compute(options.TokenHashPurpose, token, pepper))
                .ToLowerInvariant();
            if (!hashes.Contains(hash, StringComparer.Ordinal))
            {
                hashes.Add(hash);
            }
        }

        return hashes;
    }

    /// <summary>Derives the current temporary credential only when completing enrollment.</summary>
    public string CreateTemporaryPassword(string enrollmentReference) =>
        CreateTemporaryPassword(enrollmentReference, ResolveCurrentPepper());

    /// <summary>
    /// Temporary credential for the pepper that minted the outstanding invite
    /// (may be a previous pepper during rotation).
    /// </summary>
    public string CreateTemporaryPassword(string enrollmentReference, string pepper)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pepper);
        return $"{options.TemporaryPasswordPrefix}{Base64Url(Compute(options.TemporaryPasswordPurpose, enrollmentReference, pepper))}";
    }

    /// <summary>
    /// Resolves which pepper produced a stored token hash so temporary credentials match.
    /// </summary>
    public bool TryMatchTokenHash(
        string token,
        string storedTokenHash,
        out string matchedPepper)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        ArgumentException.ThrowIfNullOrWhiteSpace(storedTokenHash);
        matchedPepper = string.Empty;
        foreach (var pepper in EnumeratePeppers())
        {
            var hash = Convert.ToHexString(Compute(options.TokenHashPurpose, token, pepper))
                .ToLowerInvariant();
            if (string.Equals(hash, storedTokenHash, StringComparison.Ordinal))
            {
                matchedPepper = pepper;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Builds an enrollment URL at send or display time so the raw token need not be written to an outbox.
    /// </summary>
    public string CreateLink(string publicOrigin, string enrollmentReference)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(publicOrigin);
        return FormatLink(publicOrigin, CreateToken(enrollmentReference));
    }

    /// <summary>
    /// Rebuilds the invite link for a stored token hash so re-issue survives pepper rotation.
    /// </summary>
    public string CreateLinkMatching(
        string publicOrigin,
        string enrollmentReference,
        string storedTokenHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(publicOrigin);
        ArgumentException.ThrowIfNullOrWhiteSpace(enrollmentReference);
        ArgumentException.ThrowIfNullOrWhiteSpace(storedTokenHash);
        foreach (var pepper in EnumeratePeppers())
        {
            var token = CreateToken(enrollmentReference, pepper);
            var hash = Convert.ToHexString(Compute(options.TokenHashPurpose, token, pepper))
                .ToLowerInvariant();
            if (string.Equals(hash, storedTokenHash, StringComparison.Ordinal))
            {
                return FormatLink(publicOrigin, token);
            }
        }

        throw new InvalidOperationException(
            "No configured enrollment pepper produces the stored invite hash.");
    }

    private string FormatLink(string publicOrigin, string token)
    {
        var origin = publicOrigin.TrimEnd('/');
        var path = (options.LinkPath ?? "invite").Trim().Trim('/');
        var query = Uri.EscapeDataString(options.TokenQueryName ?? "token");
        return $"{origin}/{path}?{query}={Uri.EscapeDataString(token)}";
    }

    /// <summary>Fails fast when production pepper configuration is incomplete.</summary>
    public void ValidateConfiguration()
    {
        if (options.AllowDevelopmentPepper)
        {
            return;
        }

        var pepper = options.Pepper;
        if (string.IsNullOrWhiteSpace(pepper))
        {
            throw new InvalidOperationException(
                "EnrollmentTokenOptions.Pepper must be supplied outside Development.");
        }

        if (pepper.Length < options.MinimumPepperLength)
        {
            throw new InvalidOperationException(
                $"EnrollmentTokenOptions.Pepper must be at least {options.MinimumPepperLength} characters.");
        }

        foreach (var previous in options.PreviousPeppers)
        {
            if (string.IsNullOrWhiteSpace(previous))
            {
                throw new InvalidOperationException(
                    "EnrollmentTokenOptions.PreviousPeppers must not contain empty values.");
            }

            if (previous.Length < options.MinimumPepperLength)
            {
                throw new InvalidOperationException(
                    $"EnrollmentTokenOptions.PreviousPeppers entries must be at least {options.MinimumPepperLength} characters.");
            }
        }
    }

    private byte[] Compute(string purpose, string value, string pepper)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        ArgumentException.ThrowIfNullOrWhiteSpace(pepper);
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(pepper));
        return hmac.ComputeHash(Encoding.UTF8.GetBytes($"{purpose}\u001f{value}"));
    }

    private string ResolveCurrentPepper() => EnumeratePeppers().First();

    private IEnumerable<string> EnumeratePeppers()
    {
        if (!string.IsNullOrWhiteSpace(options.Pepper))
        {
            yield return options.Pepper;
            foreach (var previous in options.PreviousPeppers)
            {
                if (!string.IsNullOrWhiteSpace(previous) &&
                    !string.Equals(previous, options.Pepper, StringComparison.Ordinal))
                {
                    yield return previous;
                }
            }

            yield break;
        }

        if (options.AllowDevelopmentPepper &&
            !string.IsNullOrWhiteSpace(options.DevelopmentPepper))
        {
            yield return options.DevelopmentPepper;
            yield break;
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
