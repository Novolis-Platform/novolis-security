using Novolis.Storage.Abstractions;

namespace Novolis.Security.OAuth.Storage;

/// <summary>SQLite-safe refresh-token row.</summary>
public sealed class StoredRefreshToken : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Rotation family.</summary>
    public Guid FamilyId { get; set; }

    /// <summary>Global identity value.</summary>
    public Guid IdentityId { get; set; }

    /// <summary>Owning client primary key.</summary>
    public Guid ClientId { get; set; }

    /// <summary>Public client identifier.</summary>
    public string ClientPublicId { get; set; } = "";

    /// <summary>SHA-512 of the opaque secret.</summary>
    public string SecretHash { get; set; } = "";

    /// <summary>Approved scopes.</summary>
    public string Scope { get; set; } = "";

    /// <summary>Approved audience.</summary>
    public string Audience { get; set; } = "";

    /// <summary>Creation time.</summary>
    public DateTimeOffset CreatedUtc { get; set; }

    /// <summary>Expiry time.</summary>
    public DateTimeOffset ExpiresUtc { get; set; }

    /// <summary>Revocation time.</summary>
    public DateTimeOffset? RevokedUtc { get; set; }

    /// <summary>Replacement token id.</summary>
    public Guid? ReplacedById { get; set; }
}
