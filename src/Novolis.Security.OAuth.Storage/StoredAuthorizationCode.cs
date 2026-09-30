using Novolis.Storage.Abstractions;

namespace Novolis.Security.OAuth.Storage;

/// <summary>SQLite-safe Authorization Code row.</summary>
public sealed class StoredAuthorizationCode : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Hash of the opaque code secret.</summary>
    public string SecretHash { get; set; } = "";

    /// <summary>Public client identifier.</summary>
    public string ClientId { get; set; } = "";

    /// <summary>Global identity value.</summary>
    public Guid IdentityId { get; set; }

    /// <summary>Exact redirect URI.</summary>
    public string RedirectUri { get; set; } = "";

    /// <summary>PKCE challenge.</summary>
    public string CodeChallenge { get; set; } = "";

    /// <summary>PKCE method.</summary>
    public string CodeChallengeMethod { get; set; } = "S256";

    /// <summary>Approved scopes.</summary>
    public string Scope { get; set; } = "";

    /// <summary>Approved audience.</summary>
    public string Audience { get; set; } = "";

    /// <summary>Issue time.</summary>
    public DateTimeOffset IssuedUtc { get; set; }

    /// <summary>Expiry time.</summary>
    public DateTimeOffset ExpiresUtc { get; set; }

    /// <summary>Consumption time.</summary>
    public DateTimeOffset? ConsumedUtc { get; set; }

    /// <summary>Access-token jti issued on redemption.</summary>
    public string? AccessTokenJti { get; set; }

    /// <summary>Refresh family issued on redemption.</summary>
    public Guid? RefreshFamilyId { get; set; }
}
