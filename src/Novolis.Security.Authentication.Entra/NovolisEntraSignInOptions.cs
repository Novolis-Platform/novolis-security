namespace Novolis.Security.Authentication.Entra;

/// <summary>OpenID Connect settings for interactive Microsoft Entra (or MSA) sign-in.</summary>
public sealed class NovolisEntraSignInOptions
{
    /// <summary>Cookie scheme that receives the authenticated application principal after Entra completes.</summary>
    public string SignInScheme { get; set; } = "Cookies";

    /// <summary>OpenID Connect authentication scheme name.</summary>
    public string OpenIdConnectScheme { get; set; } = "NovolisEntraOpenIdConnect";

    /// <summary>
    /// Authority tenant segment: a tenant GUID, <c>organizations</c>, <c>common</c>, or <c>consumers</c>.
    /// Use <c>common</c> when both work and personal Microsoft accounts may sign in.
    /// </summary>
    public string TenantId { get; set; } = "common";

    /// <summary>Entra application (client) id.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Confidential client secret when the host is not using a certificate.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>OIDC callback path registered on the Entra application.</summary>
    public string CallbackPath { get; set; } = "/signin-oidc-novolis-entra";

    /// <summary>Relative path that challenges Entra (mapped by endpoint extensions).</summary>
    public string ChallengePath { get; set; } = "/auth/microsoft/login";

    /// <summary>Default return URL after a successful sign-in when none is supplied.</summary>
    public string DefaultReturnPath { get; set; } = "/";

    /// <summary>
    /// Absolute origins allowed as <c>returnUrl</c> after Entra completes (SPA hosts on another origin).
    /// Relative paths under the API host are always allowed.
    /// </summary>
    public IList<string> AllowedReturnOrigins { get; } = new List<string>();

    /// <summary>Whether the minimum Entra application settings are present.</summary>
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(TenantId) &&
        Guid.TryParse(ClientId, out _) &&
        !string.IsNullOrWhiteSpace(ClientSecret) &&
        CallbackPath.StartsWith("/", StringComparison.Ordinal) &&
        ChallengePath.StartsWith("/", StringComparison.Ordinal);
}
