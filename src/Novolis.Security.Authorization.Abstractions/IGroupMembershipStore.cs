using Novolis.Security.Authentication;

namespace Novolis.Security.Authorization;

/// <summary>Persists group memberships.</summary>
public interface IGroupMembershipStore
{
    /// <summary>Groups containing the identity inside the tenant.</summary>
    ValueTask<IReadOnlyList<GroupId>> FindGroupsAsync(
        TenantId tenantId,
        IdentityId identityId,
        CancellationToken cancellationToken = default);

    /// <summary>Adds a membership and bumps the tenant authorization version.</summary>
    ValueTask AddAsync(
        GroupMembership membership,
        CancellationToken cancellationToken = default);

    /// <summary>Removes a membership and bumps the tenant authorization version.</summary>
    ValueTask RemoveAsync(
        GroupMembership membership,
        CancellationToken cancellationToken = default);
}
