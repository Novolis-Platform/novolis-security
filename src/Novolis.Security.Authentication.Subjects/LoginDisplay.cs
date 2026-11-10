namespace Novolis.Security.Authentication.Subjects;

/// <summary>
/// Owner-facing login labels. Cryptographic subjects and national-id schemes stay internal;
/// owners only see email or a generic alphanumeric login.
/// </summary>
public static class LoginDisplay
{
    /// <summary>Internal scheme id for Norwegian personnummer secured subjects (never shown in UI).</summary>
    public const string NorwegianPersonNumberScheme = "no.fnr";

    /// <summary>
    /// Builds the login an instance owner works with. Secured subjects become a short alphanumeric id.
    /// </summary>
    public static string ForOwner(
        LoginSubjectKind kind,
        string? rawInput,
        string? storedSubject = null,
        string? ownerLogin = null)
    {
        if (!string.IsNullOrWhiteSpace(ownerLogin))
        {
            return ownerLogin.Trim();
        }

        return kind switch
        {
            LoginSubjectKind.Email when LoginSubjects.IsEmail(rawInput)
                => LoginSubjects.NormalizeEmail(rawInput!),
            LoginSubjectKind.SecuredNationalId when !string.IsNullOrWhiteSpace(storedSubject)
                => SecuredLoginMint.ToPublicLogin(storedSubject),
            LoginSubjectKind.OpenIdConnect when !string.IsNullOrWhiteSpace(storedSubject)
                => SecuredLoginMint.ToPublicLogin(storedSubject),
            _ => DescribeStored(storedSubject),
        };
    }

    /// <summary>Describes a stored auth subject without revealing scheme flavor.</summary>
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
            return SecuredLoginMint.ToPublicLogin(storedSubject);
        }

        return storedSubject;
    }
}
