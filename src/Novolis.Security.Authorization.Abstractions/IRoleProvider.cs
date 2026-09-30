namespace Novolis.Security.Authorization;

/// <summary>Resolves role definitions from built-in or stored catalogs.</summary>
public interface IRoleProvider
{
    /// <summary>Finds a role. Built-in roles take precedence over stored roles.</summary>
    ValueTask<RoleDefinition?> FindAsync(
        TenantId tenantId,
        RoleId roleId,
        CancellationToken cancellationToken = default);
}
