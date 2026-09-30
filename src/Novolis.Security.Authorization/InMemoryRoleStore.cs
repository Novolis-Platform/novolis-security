using System.Collections.Concurrent;

namespace Novolis.Security.Authorization;

/// <summary>Process-local stored-role catalog.</summary>
public sealed class InMemoryRoleStore : IRoleStore
{
    readonly ConcurrentDictionary<(Guid Tenant, string Role), RoleDefinition> _roles = new();

    /// <inheritdoc />
    public ValueTask<RoleDefinition?> TryGetAsync(
        TenantId tenantId,
        RoleId roleId,
        CancellationToken cancellationToken = default)
    {
        _roles.TryGetValue((tenantId.Value, roleId.Value), out var role);
        return ValueTask.FromResult(role);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(
        RoleDefinition role,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(role);
        if (role.TenantId is null)
            throw new InvalidOperationException("Stored roles must belong to a tenant.");
        _roles[(role.TenantId.Value.Value, role.Id.Value)] = role;
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<RoleDefinition>> ListAsync(
        TenantId tenantId,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<RoleDefinition> matches = _roles.Values
            .Where(role => role.TenantId == tenantId)
            .ToArray();
        return ValueTask.FromResult(matches);
    }
}
