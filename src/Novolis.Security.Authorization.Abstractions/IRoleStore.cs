namespace Novolis.Security.Authorization;

/// <summary>Persists tenant-defined custom and composite roles.</summary>
public interface IRoleStore
{
    /// <summary>Finds a stored role in the tenant.</summary>
    ValueTask<RoleDefinition?> TryGetAsync(
        TenantId tenantId,
        RoleId roleId,
        CancellationToken cancellationToken = default);

    /// <summary>Inserts or replaces a stored role after cycle and catalog validation.</summary>
    ValueTask UpsertAsync(
        RoleDefinition role,
        CancellationToken cancellationToken = default);

    /// <summary>All stored roles for the tenant.</summary>
    ValueTask<IReadOnlyList<RoleDefinition>> ListAsync(
        TenantId tenantId,
        CancellationToken cancellationToken = default);
}
