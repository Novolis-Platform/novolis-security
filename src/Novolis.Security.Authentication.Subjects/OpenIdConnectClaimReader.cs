using System.Security.Claims;

namespace Novolis.Security.Authentication.Subjects;

/// <summary>Reads common OpenID Connect claims used to admit product users.</summary>
public static class OpenIdConnectClaimReader
{
    /// <summary>Preferred email-like claim for directory matching.</summary>
    public static string? FindEmail(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return FirstNonEmpty(
            ClaimValue(principal, "preferred_username"),
            ClaimValue(principal, "email"),
            ClaimValue(principal, ClaimTypes.Email),
            principal.Identity?.Name);
    }

    /// <summary>OpenID Connect subject (<c>sub</c>) claim.</summary>
    public static string? FindSubject(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return FirstNonEmpty(
            ClaimValue(principal, "sub"),
            ClaimValue(principal, ClaimTypes.NameIdentifier));
    }

    /// <summary>Issuer claim when present on the principal.</summary>
    public static string? FindIssuer(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var iss = ClaimValue(principal, "iss");
        if (!string.IsNullOrWhiteSpace(iss))
        {
            return iss;
        }

        foreach (var claim in principal.Claims)
        {
            if (!string.IsNullOrWhiteSpace(claim.Issuer) &&
                !string.Equals(claim.Issuer, ClaimsIdentity.DefaultIssuer, StringComparison.Ordinal))
            {
                return claim.Issuer.Trim();
            }
        }

        return null;
    }

    /// <summary>
    /// Builds an OpenID Connect <see cref="LoginSubject"/> when issuer and subject claims are present.
    /// </summary>
    public static LoginSubject? TryCreateSubject(ClaimsPrincipal principal, string? fallbackIssuer = null)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var subject = FindSubject(principal);
        var issuer = FindIssuer(principal) ?? fallbackIssuer;
        if (string.IsNullOrWhiteSpace(subject) || string.IsNullOrWhiteSpace(issuer))
        {
            return null;
        }

        return new LoginSubject(
            LoginSubjectKind.OpenIdConnect,
            LoginSubjects.FormatOpenIdConnect(issuer, subject),
            LoginSubjects.NormalizeIssuer(issuer));
    }

    private static string? ClaimValue(ClaimsPrincipal principal, string claimType) =>
        principal.FindFirst(claimType)?.Value;

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return null;
    }
}
