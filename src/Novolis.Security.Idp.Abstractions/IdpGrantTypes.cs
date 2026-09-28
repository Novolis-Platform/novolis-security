namespace Novolis.Security.Idp;

/// <summary>OAuth 2.0 grant types supported by this identity library.</summary>
public static class IdpGrantTypes
{
    /// <summary>First-party resource-owner password grant (confidential clients only).</summary>
    public const string Password = "password";

    /// <summary>Service-to-service client credentials grant.</summary>
    public const string ClientCredentials = "client_credentials";

    /// <summary>Refresh-token rotation grant.</summary>
    public const string RefreshToken = "refresh_token";
}
