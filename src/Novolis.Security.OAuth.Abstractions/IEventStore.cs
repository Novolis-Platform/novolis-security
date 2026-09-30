using Novolis.Security.Authentication;

namespace Novolis.Security.OAuth;

/// <summary>
/// Observation surface for token-service outcomes. The default is a no-op.
/// Payloads never include passwords, refresh secrets, PEMs, or hashes — turn this on to watch grants, not to log credentials.
/// Distinct from <c>Novolis.Storage.Abstractions.Events.IEventStore</c> (append-only journal).
/// </summary>
public interface IEventStore
{
    /// <summary>Records one observation. Implementations must not throw into the token path.</summary>
    ValueTask RecordAsync(SecurityEvent evt, CancellationToken ct = default);
}

/// <summary>One OAuth security observation. Identifiers only.</summary>
public sealed class SecurityEvent
{
    /// <summary>UTC timestamp.</summary>
    public DateTimeOffset Utc { get; init; }

    /// <summary>One of <see cref="SecurityEventTypes"/>.</summary>
    public string Type { get; init; } = "";

    /// <summary>OAuth client_id when known.</summary>
    public string? ClientId { get; init; }

    /// <summary>Global identity when the grant involved an authenticated person.</summary>
    public IdentityId? IdentityId { get; init; }

    /// <summary>Grant type string.</summary>
    public string? GrantType { get; init; }

    /// <summary>RFC 6749 error code on failure.</summary>
    public string? Error { get; init; }
}

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
