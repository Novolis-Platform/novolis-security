using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authentication.Storage;

/// <summary>Browser authentication-session row.</summary>
public sealed class StoredAuthenticationSession : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Opaque session identifier.</summary>
    public string SessionId { get; set; } = "";

    /// <summary>Authenticated identity.</summary>
    public Guid IdentityId { get; set; }

    /// <summary>Issue time.</summary>
    public DateTimeOffset IssuedUtc { get; set; }

    /// <summary>Expiry time.</summary>
    public DateTimeOffset ExpiresUtc { get; set; }

    /// <summary>Revocation time.</summary>
    public DateTimeOffset? RevokedUtc { get; set; }
}
