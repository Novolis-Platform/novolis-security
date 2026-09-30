using Novolis.Security.Authentication;
using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authorization.Storage;

/// <summary>Repository adapter for group memberships.</summary>
public sealed class RepositoryGroupMembershipStore(
    IRepository<StoredGroupMembership> repository,
    IAuthorizationVersionStore versions) : IGroupMembershipStore
{
    /// <inheritdoc />
    public ValueTask<IReadOnlyList<GroupId>> FindGroupsAsync(
        TenantId tenantId,
        IdentityId identityId,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<GroupId> matches = repository.All()
            .Where(row => row.TenantId == tenantId.Value && row.IdentityId == identityId.Value)
            .Select(row => new GroupId(row.GroupId))
            .Distinct()
            .ToArray();
        return ValueTask.FromResult(matches);
    }

    /// <inheritdoc />
    public async ValueTask AddAsync(
        GroupMembership membership,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(membership);
        await repository.UpsertAsync(
            new StoredGroupMembership
            {
                Id = Guid.NewGuid(),
                TenantId = membership.TenantId.Value,
                GroupId = membership.GroupId.Value,
                IdentityId = membership.IdentityId.Value,
            },
            cancellationToken).ConfigureAwait(false);
        await versions.IncrementAsync(membership.TenantId, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask RemoveAsync(
        GroupMembership membership,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(membership);
        foreach (var row in repository.All().Where(r =>
                     r.TenantId == membership.TenantId.Value
                     && r.GroupId == membership.GroupId.Value
                     && r.IdentityId == membership.IdentityId.Value))
            await repository.DeleteAsync(row.Id, cancellationToken).ConfigureAwait(false);
        await versions.IncrementAsync(membership.TenantId, cancellationToken).ConfigureAwait(false);
    }
}
