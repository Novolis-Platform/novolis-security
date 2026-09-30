using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authorization.Storage;

/// <summary>Persisted group membership row.</summary>
public sealed class StoredGroupMembership : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Owning tenant.</summary>
    public Guid TenantId { get; set; }

    /// <summary>Group identifier.</summary>
    public Guid GroupId { get; set; }

    /// <summary>Member identity.</summary>
    public Guid IdentityId { get; set; }
}
