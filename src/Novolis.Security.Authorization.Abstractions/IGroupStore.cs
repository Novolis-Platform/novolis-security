namespace Novolis.Security.Authorization;

/// <summary>Persists tenant-scoped groups.</summary>
public interface IGroupStore
{
    /// <summary>Finds a group inside a tenant.</summary>
    ValueTask<Group?> TryGetAsync(
        TenantId tenantId,
        GroupId groupId,
        CancellationToken cancellationToken = default);

    /// <summary>Inserts or replaces a group.</summary>
    ValueTask UpsertAsync(Group group, CancellationToken cancellationToken = default);
}
