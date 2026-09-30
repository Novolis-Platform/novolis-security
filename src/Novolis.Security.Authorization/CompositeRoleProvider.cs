namespace Novolis.Security.Authorization;

/// <summary>Built-in roles take precedence over stored roles.</summary>
public sealed class CompositeRoleProvider(
    BuiltInRoleProvider builtIn,
    StoredRoleProvider stored) : IRoleProvider
{
    /// <inheritdoc />
    public async ValueTask<RoleDefinition?> FindAsync(
        TenantId tenantId,
        RoleId roleId,
        CancellationToken cancellationToken = default)
    {
        var built = await builtIn.FindAsync(tenantId, roleId, cancellationToken).ConfigureAwait(false);
        return built ?? await stored.FindAsync(tenantId, roleId, cancellationToken).ConfigureAwait(false);
    }
}
