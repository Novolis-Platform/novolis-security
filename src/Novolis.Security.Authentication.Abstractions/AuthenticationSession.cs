namespace Novolis.Security.Authentication;

/// <summary>Browser authentication session used by the OAuth authorization endpoint.</summary>
public sealed class AuthenticationSession
{
    /// <summary>Opaque session identifier sent in the browser cookie.</summary>
    public string SessionId { get; set; } = "";

    /// <summary>Global identity authenticated by this session.</summary>
    public IdentityId IdentityId { get; set; }

    /// <summary>Session creation time.</summary>
    public DateTimeOffset IssuedUtc { get; set; }

    /// <summary>Session expiry time.</summary>
    public DateTimeOffset ExpiresUtc { get; set; }

    /// <summary>When set, the session can no longer authenticate an authorization request.</summary>
    public DateTimeOffset? RevokedUtc { get; set; }

    /// <summary>Whether the session is currently usable.</summary>
    public bool IsActive(DateTimeOffset now) =>
        RevokedUtc is null && ExpiresUtc > now;
}
