using Novolis.Security.Authentication;

namespace Novolis.Security.OAuth;

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
