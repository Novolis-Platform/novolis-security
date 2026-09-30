using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authorization.Storage;

/// <summary>Persisted custom or composite role row.</summary>
public sealed class StoredRole : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Owning tenant.</summary>
    public Guid TenantId { get; set; }

    /// <summary>Stable role identifier.</summary>
    public string RoleId { get; set; } = "";

    /// <summary>Packed permission identifiers.</summary>
    public string Permissions { get; set; } = "";

    /// <summary>Packed included role identifiers.</summary>
    public string IncludedRoles { get; set; } = "";
}
