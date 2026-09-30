namespace Novolis.Security.OAuth;

/// <summary>OAuth error codes used by token and authorization endpoints.</summary>
public static class OAuthTokenErrors
{
    /// <summary>Malformed or missing request fields.</summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>Unknown client or bad client secret.</summary>
    public const string InvalidClient = "invalid_client";

    /// <summary>Bad authorization code, disabled identity, or unusable refresh token.</summary>
    public const string InvalidGrant = "invalid_grant";

    /// <summary>Client is not allowed to use the requested grant.</summary>
    public const string UnauthorizedClient = "unauthorized_client";

    /// <summary>Grant type is not implemented.</summary>
    public const string UnsupportedGrantType = "unsupported_grant_type";

    /// <summary>Requested scopes do not intersect the client's allow-list.</summary>
    public const string InvalidScope = "invalid_scope";

    /// <summary>Authorization request was denied by the authenticated user.</summary>
    public const string AccessDenied = "access_denied";

    /// <summary>Redirect URI or response type is not allowed.</summary>
    public const string InvalidRequestObject = "invalid_request_object";

    /// <summary>Too many attempts in the cache window. HTTP layer maps this to 429.</summary>
    public const string RateLimited = "temporarily_unavailable";
}
