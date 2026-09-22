using Novolis.Storage.Abstractions;

namespace Novolis.Security.Idp;

/// <summary>Opaque refresh token row. The raw secret is never stored — only <see cref="SecretHash"/>.</summary>
public sealed class IdpRefreshToken : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Rotation family. Reuse of a revoked token revokes every row with this id.</summary>
    public Guid FamilyId { get; set; }

    /// <summary><see cref="AccountId"/> value of the owner, or <see cref="Guid.Empty"/> when no account is involved.</summary>
    public Guid AccountId { get; set; }

    /// <summary>Owning client primary key.</summary>
    public Guid ClientId { get; set; }

    /// <summary>SHA-512 of the secret segment, Base64. The raw secret is never stored.</summary>
    public string SecretHash { get; set; } = "";

    /// <summary>Space-separated scopes originally granted. Refresh cannot expand this set.</summary>
    public string Scope { get; set; } = "";

    /// <summary>UTC expiry.</summary>
    public DateTimeOffset ExpiresUtc { get; set; }

    /// <summary>Set when rotated or explicitly revoked.</summary>
    public DateTimeOffset? RevokedUtc { get; set; }

    /// <summary>Replacement token id after rotation.</summary>
    public Guid? ReplacedById { get; set; }
}
