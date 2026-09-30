using Novolis.Security.Authentication;

namespace Novolis.Security.Authorization;

/// <summary>Persists tenant-scoped role assignments.</summary>
public interface IRoleAssignmentStore
{
    /// <summary>Roles assigned directly to the identity.</summary>
    ValueTask<IReadOnlyList<RoleId>> FindIdentityRolesAsync(
        TenantId tenantId,
        IdentityId identityId,
        CancellationToken cancellationToken = default);

    /// <summary>Roles assigned to the group.</summary>
    ValueTask<IReadOnlyList<RoleId>> FindGroupRolesAsync(
        TenantId tenantId,
        GroupId groupId,
        CancellationToken cancellationToken = default);

    /// <summary>Assigns a role to an identity.</summary>
    ValueTask AssignIdentityAsync(
        IdentityRoleAssignment assignment,
        CancellationToken cancellationToken = default);

    /// <summary>Removes a role from an identity.</summary>
    ValueTask RemoveIdentityAsync(
        IdentityRoleAssignment assignment,
        CancellationToken cancellationToken = default);

    /// <summary>Assigns a role to a group.</summary>
    ValueTask AssignGroupAsync(
        GroupRoleAssignment assignment,
        CancellationToken cancellationToken = default);

    /// <summary>Removes a role from a group.</summary>
    ValueTask RemoveGroupAsync(
        GroupRoleAssignment assignment,
        CancellationToken cancellationToken = default);
}
