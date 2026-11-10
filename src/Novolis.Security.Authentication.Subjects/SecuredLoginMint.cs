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

    /// <summary>Builds <c>sec:{scheme}:{hash}</c> for a normalized sensitive identifier (current pepper).</summary>
    public string Create(string scheme, string normalizedValue) =>
        CreateWithPepper(scheme, normalizedValue, ResolveCurrentPepper());

    /// <summary>
    /// Current pepper subject first, then previous peppers — used at sign-in so rotation
    /// does not lock out existing workplaces.
    /// </summary>
    public IReadOnlyList<string> CreateCandidates(string scheme, string normalizedValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        ArgumentException.ThrowIfNullOrWhiteSpace(normalizedValue);
        var subjects = new List<string>();
        foreach (var pepper in EnumeratePeppers())
        {
            var subject = CreateWithPepper(scheme, normalizedValue, pepper);
            if (!subjects.Contains(subject, StringComparer.Ordinal))
            {
                subjects.Add(subject);
            }
        }

        return subjects;
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
                "SecuredLoginOptions.Pepper must be supplied outside Development.");
        }

        if (pepper.Length < options.MinimumPepperLength)
        {
            throw new InvalidOperationException(
                $"SecuredLoginOptions.Pepper must be at least {options.MinimumPepperLength} characters.");
        }

        foreach (var previous in options.PreviousPeppers)
        {
            if (string.IsNullOrWhiteSpace(previous))
            {
                throw new InvalidOperationException(
                    "SecuredLoginOptions.PreviousPeppers must not contain empty values.");
            }

            if (previous.Length < options.MinimumPepperLength)
            {
                throw new InvalidOperationException(
                    $"SecuredLoginOptions.PreviousPeppers entries must be at least {options.MinimumPepperLength} characters.");
            }
        }
    }

    private string CreateWithPepper(string scheme, string normalizedValue, string pepper)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        ArgumentException.ThrowIfNullOrWhiteSpace(normalizedValue);
        var purpose = $"{options.Purpose}/{scheme.Trim().ToLowerInvariant()}";
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(pepper));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes($"{purpose}\u001f{normalizedValue}"));
        return $"{Prefix}{scheme.Trim().ToLowerInvariant()}:{Base64Url(hash)}";
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
            "SecuredLoginOptions.Pepper must be supplied outside Development.");
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
