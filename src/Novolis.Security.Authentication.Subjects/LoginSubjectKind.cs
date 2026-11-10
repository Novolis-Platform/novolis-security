namespace Novolis.Security.Authentication.Subjects;

/// <summary>How a product login subject is identified.</summary>
public enum LoginSubjectKind
{
    /// <summary>Default: an email address used as the sign-in identifier.</summary>
    Email = 0,

    /// <summary>OpenID Connect issuer + subject (preferred when an external IdP is available).</summary>
    OpenIdConnect = 1,

    /// <summary>
    /// Sensitive national id turned into a one-way secured subject.
    /// Owners see a masked login label; auth stores only the HMAC subject.
    /// </summary>
    SecuredNationalId = 2,
}
