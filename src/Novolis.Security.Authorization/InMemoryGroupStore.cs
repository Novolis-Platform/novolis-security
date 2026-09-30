using System.Collections.Concurrent;

namespace Novolis.Security.Authorization;

/// <summary>Process-local group store.</summary>
public sealed class InMemoryGroupStore : IGroupStore
{
    readonly ConcurrentDictionary<(Guid Tenant, Guid Group), Group> _groups = new();

    /// <inheritdoc />
    public ValueTask<Group?> TryGetAsync(
        TenantId tenantId,
        GroupId groupId,
        CancellationToken cancellationToken = default)
    {
        _groups.TryGetValue((tenantId.Value, groupId.Value), out var group);
        return ValueTask.FromResult(group);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(Group group, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(group);
        _groups[(group.TenantId.Value, group.Id.Value)] = group;
        return ValueTask.CompletedTask;
    }
}
