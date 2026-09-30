using Novolis.Storage.Abstractions;

namespace Novolis.Security.OAuth.Storage;

/// <summary>SQLite-safe OAuth client row. List fields are packed as unit-separator strings.</summary>
public sealed class StoredOAuthClient : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Public client identifier.</summary>
    public string ClientId { get; set; } = "";

    /// <summary>Stored <see cref="OAuthClientType"/> value.</summary>
    public int ClientType { get; set; }

    /// <summary>Hashed confidential-client secret.</summary>
    public string SecretHash { get; set; } = "";

    /// <summary>When true, every grant is rejected.</summary>
    public bool Disabled { get; set; }

    /// <summary>Packed grant types.</summary>
    public string AllowedGrantTypes { get; set; } = "";

    /// <summary>Packed exact redirect URIs.</summary>
    public string AllowedRedirectUris { get; set; } = "";

    /// <summary>Packed scopes.</summary>
    public string AllowedScopes { get; set; } = "";

    /// <summary>Packed audiences.</summary>
    public string AllowedAudiences { get; set; } = "";
}
