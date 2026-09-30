using System.Collections.Concurrent;
using Novolis.Security.Authentication;

namespace Novolis.Security.Authorization;

/// <summary>Process-local group membership store.</summary>
public sealed class InMemoryGroupMembershipStore(IAuthorizationVersionStore versions) : IGroupMembershipStore
{
    readonly ConcurrentDictionary<(Guid Tenant, Guid Group, Guid Identity), GroupMembership> _memberships = new();

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<GroupId>> FindGroupsAsync(
        TenantId tenantId,
        IdentityId identityId,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<GroupId> matches = _memberships.Values
            .Where(m => m.TenantId == tenantId && m.IdentityId == identityId)
            .Select(m => m.GroupId)
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
        _memberships[(membership.TenantId.Value, membership.GroupId.Value, membership.IdentityId.Value)] = membership;
        await versions.IncrementAsync(membership.TenantId, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask RemoveAsync(
        GroupMembership membership,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(membership);
        _memberships.TryRemove((membership.TenantId.Value, membership.GroupId.Value, membership.IdentityId.Value), out _);
        await versions.IncrementAsync(membership.TenantId, cancellationToken).ConfigureAwait(false);
    }
}
