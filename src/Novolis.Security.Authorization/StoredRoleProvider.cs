namespace Novolis.Security.Authorization;

/// <summary>Resolves tenant-defined stored roles.</summary>
public sealed class StoredRoleProvider(IRoleStore store) : IRoleProvider
{
    /// <inheritdoc />
    public ValueTask<RoleDefinition?> FindAsync(
        TenantId tenantId,
        RoleId roleId,
        CancellationToken cancellationToken = default) =>
        store.TryGetAsync(tenantId, roleId, cancellationToken);
}
