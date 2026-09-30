using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authorization.Storage;

/// <summary>Repository adapter for stored roles.</summary>
public sealed class RepositoryRoleStore(IRepository<StoredRole> repository) : IRoleStore
{
    const char PackSeparator = '\u001f';

    /// <inheritdoc />
    public ValueTask<RoleDefinition?> TryGetAsync(
        TenantId tenantId,
        RoleId roleId,
        CancellationToken cancellationToken = default)
    {
        var match = repository.All()
            .FirstOrDefault(row => row.TenantId == tenantId.Value && string.Equals(row.RoleId, roleId.Value, StringComparison.Ordinal));
        return ValueTask.FromResult(match is null ? null : ToDefinition(match));
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(
        RoleDefinition role,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(role);
        if (role.TenantId is null)
            throw new InvalidOperationException("Stored roles must belong to a tenant.");

        var existing = repository.All()
            .FirstOrDefault(row => row.TenantId == role.TenantId.Value.Value
                && string.Equals(row.RoleId, role.Id.Value, StringComparison.Ordinal));
        return repository.UpsertAsync(
            new StoredRole
            {
                Id = existing?.Id ?? Guid.NewGuid(),
                TenantId = role.TenantId.Value.Value,
                RoleId = role.Id.Value,
                Permissions = string.Join(PackSeparator, role.Permissions.Select(p => p.Value)),
                IncludedRoles = string.Join(PackSeparator, role.IncludedRoles.Select(r => r.Value)),
            },
            cancellationToken);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<RoleDefinition>> ListAsync(
        TenantId tenantId,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<RoleDefinition> matches = repository.All()
            .Where(row => row.TenantId == tenantId.Value)
            .Select(ToDefinition)
            .ToArray();
        return ValueTask.FromResult(matches);
    }

    static RoleDefinition ToDefinition(StoredRole row) =>
        new(
            new RoleId(row.RoleId),
            new TenantId(row.TenantId),
            Unpack(row.Permissions).Select(v => new PermissionId(v)).ToHashSet(),
            Unpack(row.IncludedRoles).Select(v => new RoleId(v)).ToHashSet(),
            IsBuiltIn: false);

    static IEnumerable<string> Unpack(string packed) =>
        string.IsNullOrEmpty(packed)
            ? []
            : packed.Split(PackSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
