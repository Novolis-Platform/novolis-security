using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authorization.Storage;

/// <summary>Repository adapter for groups.</summary>
public sealed class RepositoryGroupStore(IRepository<StoredGroup> repository) : IGroupStore
{
    /// <inheritdoc />
    public async ValueTask<Group?> TryGetAsync(
        TenantId tenantId,
        GroupId groupId,
        CancellationToken cancellationToken = default)
    {
        var row = await repository.TryGetAsync(groupId.Value, cancellationToken).ConfigureAwait(false);
        if (row is null || row.TenantId != tenantId.Value)
            return null;
        return new Group(new GroupId(row.Id), new TenantId(row.TenantId), row.Name);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(Group group, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(group);
        return repository.UpsertAsync(
            new StoredGroup
            {
                Id = group.Id.Value,
                TenantId = group.TenantId.Value,
                Name = group.Name,
            },
            cancellationToken);
    }
}
