namespace Novolis.Security.Authorization;

/// <summary>Rejects unknown permissions, built-in overrides, and composite cycles at mutation time.</summary>
public sealed class ValidatingRoleStore(
    IRoleStore inner,
    IPermissionCatalog catalog,
    BuiltInRoleRegistry builtIn,
    IAuthorizationVersionStore versions) : IRoleStore
{
    /// <inheritdoc />
    public ValueTask<RoleDefinition?> TryGetAsync(
        TenantId tenantId,
        RoleId roleId,
        CancellationToken cancellationToken = default) =>
        inner.TryGetAsync(tenantId, roleId, cancellationToken);

    /// <inheritdoc />
    public async ValueTask UpsertAsync(
        RoleDefinition role,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(role);
        if (role.TenantId is null)
            throw new InvalidOperationException("Stored roles must belong to a tenant.");
        if (builtIn.Find(role.Id) is not null)
            throw new InvalidOperationException($"Stored role '{role.Id.Value}' cannot override a built-in role.");
        foreach (var permission in role.Permissions)
        {
            if (!catalog.Contains(permission))
                throw new InvalidOperationException($"Unknown permission '{permission.Value}'.");
        }

        var known = (await inner.ListAsync(role.TenantId.Value, cancellationToken).ConfigureAwait(false))
            .ToDictionary(r => r.Id.Value, StringComparer.Ordinal);
        known[role.Id.Value] = role;
        CompositeRoleGraph.ThrowIfCycle(role.Id, role.IncludedRoles, known);
        await inner.UpsertAsync(role, cancellationToken).ConfigureAwait(false);
        await versions.IncrementAsync(role.TenantId.Value, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<RoleDefinition>> ListAsync(
        TenantId tenantId,
        CancellationToken cancellationToken = default) =>
        inner.ListAsync(tenantId, cancellationToken);
}
