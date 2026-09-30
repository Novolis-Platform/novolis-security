namespace Novolis.Security.Authorization;

/// <summary>Resolves code-backed roles.</summary>
public sealed class BuiltInRoleProvider(BuiltInRoleRegistry registry) : IRoleProvider
{
    /// <inheritdoc />
    public ValueTask<RoleDefinition?> FindAsync(
        TenantId tenantId,
        RoleId roleId,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(registry.Find(roleId));
}
