namespace Novolis.Security.Authentication.Subjects;

/// <summary>
/// Owner-facing login labels. Cryptographic subjects stay internal as one-way hashes;
/// owners see either an email or an obscured mask — never the hash or scheme flavor.
/// </summary>
public static class LoginDisplay
{
    /// <summary>What owners see after a secured login is stored (one-way hash; not reversible).</summary>
    public const string ObscuredLogin = "********";

    /// <summary>Internal scheme id for Norwegian personnummer secured subjects (never shown in UI).</summary>
    public const string NorwegianPersonNumberScheme = "no.fnr";

    /// <summary>Internal scheme id for generic alphanumeric secured logins (never shown in UI).</summary>
    public const string AlphanumericScheme = "login";

    /// <summary>
    /// Builds the login an instance owner works with after invite.
    /// Secured subjects always become <see cref="ObscuredLogin"/>.
    /// </summary>
    public static string ForOwner(
        LoginSubjectKind kind,
        string? rawInput,
        string? storedSubject = null,
        string? ownerLogin = null)
    {
        if (kind == LoginSubjectKind.SecuredNationalId ||
            SecuredLoginMint.IsSecured(storedSubject) ||
            string.Equals(ownerLogin, ObscuredLogin, StringComparison.Ordinal))
        {
            return ObscuredLogin;
        }

        if (!string.IsNullOrWhiteSpace(ownerLogin) &&
            !SecuredLoginMint.IsSecured(ownerLogin))
        {
            return ownerLogin.Trim();
        }

        return kind switch
        {
            LoginSubjectKind.Email when LoginSubjects.IsEmail(rawInput)
                => LoginSubjects.NormalizeEmail(rawInput!),
            LoginSubjectKind.OpenIdConnect
                => ObscuredLogin,
            _ => DescribeStored(storedSubject),
        };
    }

    /// <summary>Describes a stored auth subject without revealing secrets or flavor.</summary>
    public static string DescribeStored(string? storedSubject)
    {
        if (string.IsNullOrWhiteSpace(storedSubject))
        {
            return string.Empty;
        }

        if (LoginSubjects.IsEmail(storedSubject))
        {
            return LoginSubjects.NormalizeEmail(storedSubject);
        }

        if (SecuredLoginMint.IsSecured(storedSubject) ||
            storedSubject.StartsWith(LoginSubjects.OpenIdConnectPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return ObscuredLogin;
        }

        return storedSubject;
    }
}
