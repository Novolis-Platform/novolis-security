using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authorization.Storage;

/// <summary>Persisted identity or group role assignment.</summary>
public sealed class StoredRoleAssignment : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Owning tenant.</summary>
    public Guid TenantId { get; set; }

    /// <summary>Assigned identity, or empty when this is a group assignment.</summary>
    public Guid IdentityId { get; set; }

    /// <summary>Assigned group, or empty when this is an identity assignment.</summary>
    public Guid GroupId { get; set; }

    /// <summary>Assigned role identifier.</summary>
    public string RoleId { get; set; } = "";
}
