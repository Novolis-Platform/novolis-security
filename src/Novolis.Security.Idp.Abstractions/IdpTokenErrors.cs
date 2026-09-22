namespace Novolis.Security.Idp;

/// <summary>RFC 6749 error codes returned by <see cref="IIdpTokenService"/>.</summary>
public static class IdpTokenErrors
{
    /// <summary>Malformed or missing request fields.</summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>Unknown client or bad client secret.</summary>
    public const string InvalidClient = "invalid_client";

    /// <summary>Bad username/password, disabled account, or unusable refresh token.</summary>
    public const string InvalidGrant = "invalid_grant";

    /// <summary>Client is not allowed to use the requested grant.</summary>
    public const string UnauthorizedClient = "unauthorized_client";

    /// <summary>Grant type is not implemented.</summary>
    public const string UnsupportedGrantType = "unsupported_grant_type";

    /// <summary>Requested scopes do not intersect the client's allow-list.</summary>
    public const string InvalidScope = "invalid_scope";
}
