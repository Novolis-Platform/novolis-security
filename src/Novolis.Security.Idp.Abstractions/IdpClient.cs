using Novolis.Storage.Abstractions;

namespace Novolis.Security.Idp;

/// <summary>Confidential OAuth client persisted through <c>IRepository&lt;IdpClient&gt;</c>.</summary>
public sealed class IdpClient : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Public client identifier sent as <c>client_id</c>.</summary>
    public string ClientId { get; set; } = "";

    /// <summary>Hashed client secret from <c>IdpCredentialHasher</c>.</summary>
    public string SecretHash { get; set; } = "";

    /// <summary>When false, all grants are rejected. The MVP requires confidential clients.</summary>
    public bool Confidential { get; set; } = true;

    /// <summary>Allowed <see cref="IdpGrantTypes"/> values.</summary>
    public List<string> AllowedGrantTypes { get; set; } = [];

    /// <summary>Scopes the client may request.</summary>
    public List<string> AllowedScopes { get; set; } = [];

    /// <summary>Optional audience allow-list. Empty means use <see cref="IdpOptions.Audiences"/>.</summary>
    public List<string> AllowedAudiences { get; set; } = [];
}
