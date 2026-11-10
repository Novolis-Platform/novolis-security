using System.Diagnostics.CodeAnalysis;

namespace Novolis.Security.Authentication.Subjects;

/// <summary>Parse, normalize, and format product login subjects.</summary>
public static class LoginSubjects
{
    /// <summary>Stable prefix for OpenID Connect login keys.</summary>
    public const string OpenIdConnectPrefix = "oidc:";

    /// <summary>Whether a value looks like a usable email login.</summary>
    public static bool IsEmail(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        var at = trimmed.IndexOf('@');
        return at > 0 &&
               at < trimmed.Length - 3 &&
               trimmed.IndexOf('.', at) > at + 1 &&
               !trimmed.Contains(' ', StringComparison.Ordinal) &&
               !trimmed.StartsWith(OpenIdConnectPrefix, StringComparison.OrdinalIgnoreCase) &&
               !SecuredLoginMint.IsSecured(trimmed);
    }

    /// <summary>Normalizes an email for storage and comparison.</summary>
    public static string NormalizeEmail(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        return email.Trim().ToLowerInvariant();
    }

    /// <summary>Builds a stable OpenID Connect login key from issuer and subject.</summary>
    public static string FormatOpenIdConnect(string issuer, string subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        return $"{OpenIdConnectPrefix}{NormalizeIssuer(issuer)}:{NormalizeSubject(subject)}";
    }

    /// <summary>Creates a validated <see cref="LoginSubject"/> for email or OpenID Connect.</summary>
    public static bool TryCreate(
        LoginSubjectKind kind,
        string? value,
        string? issuer,
        [NotNullWhen(true)] out LoginSubject? subject,
        [NotNullWhen(false)] out string? error)
    {
        subject = null;
        error = null;
        switch (kind)
        {
            case LoginSubjectKind.Email:
                if (!IsEmail(value))
                {
                    error = "Enter a valid email address.";
                    return false;
                }

                subject = new LoginSubject(LoginSubjectKind.Email, NormalizeEmail(value!));
                return true;

            case LoginSubjectKind.OpenIdConnect:
                if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(value))
                {
                    error = "OpenID Connect invites need an issuer and subject.";
                    return false;
                }

                subject = new LoginSubject(
                    LoginSubjectKind.OpenIdConnect,
                    FormatOpenIdConnect(issuer, value),
                    NormalizeIssuer(issuer));
                return true;

            case LoginSubjectKind.SecuredNationalId:
                error =
                    "Secured national-id logins must be minted with SecuredLoginMint and NorwegianPersonNumber.";
                return false;

            default:
                error = "Unsupported login subject kind.";
                return false;
        }
    }

    /// <summary>
    /// Creates a secured Norwegian personnummer subject and an owner-facing login label.
    /// The digits are not retained on the returned subject.
    /// </summary>
    public static bool TryCreateNorwegianPersonNumber(
        string? personNumber,
        SecuredLoginMint mint,
        [NotNullWhen(true)] out LoginSubject? subject,
        [NotNullWhen(true)] out string? ownerLogin,
        [NotNullWhen(false)] out string? error)
    {
        ArgumentNullException.ThrowIfNull(mint);
        subject = null;
        ownerLogin = null;
        error = null;
        if (!NorwegianPersonNumber.TryNormalize(personNumber, out var digits))
        {
            error = "Enter a valid 11-digit Norwegian personnummer.";
            return false;
        }

        var secured = mint.Create(LoginDisplay.NorwegianPersonNumberScheme, digits);
        subject = new LoginSubject(LoginSubjectKind.SecuredNationalId, secured);
        ownerLogin = SecuredLoginMint.ToPublicLogin(secured);
        return true;
    }

    /// <summary>Parses a stored login string into a typed subject.</summary>
    public static LoginSubject Parse(string login)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(login);
        var trimmed = login.Trim();
        if (trimmed.StartsWith(OpenIdConnectPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var remainder = trimmed[OpenIdConnectPrefix.Length..];
            var split = remainder.IndexOf(':');
            if (split <= 0 || split >= remainder.Length - 1)
            {
                throw new FormatException("OpenID Connect login keys must be oidc:{issuer}:{subject}.");
            }

            var issuer = remainder[..split];
            var subject = remainder[(split + 1)..];
            return new LoginSubject(
                LoginSubjectKind.OpenIdConnect,
                FormatOpenIdConnect(issuer, subject),
                NormalizeIssuer(issuer));
        }

        if (SecuredLoginMint.IsSecured(trimmed))
        {
            return new LoginSubject(LoginSubjectKind.SecuredNationalId, trimmed);
        }

        if (!IsEmail(trimmed))
        {
            throw new FormatException(
                "Login is neither a valid email, OpenID Connect key, nor secured subject.");
        }

        return new LoginSubject(LoginSubjectKind.Email, NormalizeEmail(trimmed));
    }

    /// <summary>Tries to parse a stored login string.</summary>
    public static bool TryParse(string? login, [NotNullWhen(true)] out LoginSubject? subject)
    {
        subject = null;
        if (string.IsNullOrWhiteSpace(login))
        {
            return false;
        }

        try
        {
            subject = Parse(login);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Normalizes an OIDC issuer URL or identifier.</summary>
    public static string NormalizeIssuer(string issuer)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        return issuer.Trim().TrimEnd('/').ToLowerInvariant();
    }

    /// <summary>Normalizes an OIDC subject claim.</summary>
    public static string NormalizeSubject(string subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        return subject.Trim();
    }
}
