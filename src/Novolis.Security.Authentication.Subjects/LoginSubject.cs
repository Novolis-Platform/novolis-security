namespace Novolis.Security.Authentication.Subjects;

/// <summary>
/// Normalized product login subject. Stored as <see cref="Value"/> on the product user row;
/// Authentication identities still use their own identifier string.
/// </summary>
public sealed record LoginSubject(LoginSubjectKind Kind, string Value, string? Issuer = null)
{
    /// <summary>Whether this subject is an email login.</summary>
    public bool IsEmail => Kind == LoginSubjectKind.Email;

    /// <summary>Whether this subject is an OpenID Connect issuer+subject key.</summary>
    public bool IsOpenIdConnect => Kind == LoginSubjectKind.OpenIdConnect;
}
