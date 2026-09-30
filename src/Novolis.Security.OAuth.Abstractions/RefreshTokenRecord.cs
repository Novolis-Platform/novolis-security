using Novolis.Security.Authentication;

namespace Novolis.Security.OAuth;

/// <summary>Opaque refresh-token record. The raw secret is never persisted.</summary>
public sealed class RefreshTokenRecord : Novolis.Storage.Abstractions.IHasId
{
    /// <summary>Internal token identifier carried only in the opaque wire format.</summary>
    public Guid Id { get; set; }

    /// <summary>Rotation family and authorization-grant lineage.</summary>
    public Guid FamilyId { get; set; }

    /// <summary>Stable global identity bound to this grant.</summary>
    public IdentityId IdentityId { get; set; }

    /// <summary>Owning client primary key.</summary>
    public Guid ClientId { get; set; }

    /// <summary>Public OAuth client identifier for audits and migration.</summary>
    public string ClientPublicId { get; set; } = "";

    /// <summary>SHA-512 of the opaque secret segment, Base64.</summary>
    public string SecretHash { get; set; } = "";

    /// <summary>Space-separated scopes originally granted.</summary>
    public string Scope { get; set; } = "";

    /// <summary>One approved resource-server audience.</summary>
    public string Audience { get; set; } = "";

    /// <summary>Creation time.</summary>
    public DateTimeOffset CreatedUtc { get; set; }

    /// <summary>Expiry time.</summary>
    public DateTimeOffset ExpiresUtc { get; set; }

    /// <summary>Set when rotated, replayed, or explicitly revoked.</summary>
    public DateTimeOffset? RevokedUtc { get; set; }

    /// <summary>Replacement token id after rotation.</summary>
    public Guid? ReplacedById { get; set; }

    /// <summary>Absolute expiry of the rotation family. Copied on every rotation and never extended.</summary>
    public DateTimeOffset FamilyExpiresUtc { get; set; }

    /// <summary>DPoP JWK thumbprint bound to this family, when issued with DPoP.</summary>
    public string? CnfJkt { get; set; }

    /// <summary>Certificate thumbprint bound to this family, when issued with mTLS.</summary>
    public string? CnfX5tS256 { get; set; }
}
