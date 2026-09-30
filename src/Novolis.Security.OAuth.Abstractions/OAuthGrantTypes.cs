namespace Novolis.Security.OAuth;

/// <summary>OAuth 2.0 grant types supported by the Novolis authorization server.</summary>
public static class OAuthGrantTypes
{
    /// <summary>Authorization Code grant.</summary>
    public const string AuthorizationCode = "authorization_code";

    /// <summary>Service-to-service client credentials grant.</summary>
    public const string ClientCredentials = "client_credentials";

    /// <summary>Refresh-token rotation grant.</summary>
    public const string RefreshToken = "refresh_token";
}
