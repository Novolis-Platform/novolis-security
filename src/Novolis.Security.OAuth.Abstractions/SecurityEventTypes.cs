using Novolis.Security.Authentication;

namespace Novolis.Security.OAuth;

/// <summary>Event type names. Stable strings for implementers who switch on <see cref="SecurityEvent.Type"/>.</summary>
public static class SecurityEventTypes
{
    /// <summary>Authorization Code was issued.</summary>
    public const string AuthorizationCodeIssued = "authorization_code_issued";

    /// <summary>Authorization Code was redeemed.</summary>
    public const string AuthorizationCodeRedeemed = "authorization_code_redeemed";

    /// <summary>Access token minted.</summary>
    public const string TokenIssued = "token_issued";

    /// <summary>Issue failed (invalid_client, invalid_grant, …).</summary>
    public const string TokenDenied = "token_denied";

    /// <summary>Refresh token rotated successfully.</summary>
    public const string RefreshTokenRotated = "refresh_token_rotated";

    /// <summary>Presented refresh token was already spent; family revoked.</summary>
    public const string RefreshReuseDetected = "refresh_reuse_detected";

    /// <summary>Token revocation succeeded.</summary>
    public const string TokenRevoked = "token_revoked";

    /// <summary>Attempt blocked by cache rate limit.</summary>
    public const string RateLimited = "rate_limited";
}
