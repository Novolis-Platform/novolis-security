using System.Collections.Concurrent;
using Novolis.Security.Authentication;

namespace Novolis.Security.Authorization;

/// <summary>Process-local role assignments.</summary>
public sealed class InMemoryRoleAssignmentStore(IAuthorizationVersionStore versions) : IRoleAssignmentStore
{
    readonly ConcurrentDictionary<(Guid Tenant, Guid Identity, string Role), IdentityRoleAssignment> _identities = new();
    readonly ConcurrentDictionary<(Guid Tenant, Guid Group, string Role), GroupRoleAssignment> _groups = new();

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<RoleId>> FindIdentityRolesAsync(
        TenantId tenantId,
        IdentityId identityId,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<RoleId> matches = _identities.Values
            .Where(a => a.TenantId == tenantId && a.IdentityId == identityId)
            .Select(a => a.RoleId)
            .Distinct()
            .ToArray();
        return ValueTask.FromResult(matches);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<RoleId>> FindGroupRolesAsync(
        TenantId tenantId,
        GroupId groupId,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<RoleId> matches = _groups.Values
            .Where(a => a.TenantId == tenantId && a.GroupId == groupId)
            .Select(a => a.RoleId)
            .Distinct()
            .ToArray();
        return ValueTask.FromResult(matches);
    }

    /// <inheritdoc />
    public async ValueTask AssignIdentityAsync(
        IdentityRoleAssignment assignment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        _identities[(assignment.TenantId.Value, assignment.IdentityId.Value, assignment.RoleId.Value)] = assignment;
        await versions.IncrementAsync(assignment.TenantId, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask RemoveIdentityAsync(
        IdentityRoleAssignment assignment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        _identities.TryRemove((assignment.TenantId.Value, assignment.IdentityId.Value, assignment.RoleId.Value), out _);
        await versions.IncrementAsync(assignment.TenantId, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask AssignGroupAsync(
        GroupRoleAssignment assignment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        _groups[(assignment.TenantId.Value, assignment.GroupId.Value, assignment.RoleId.Value)] = assignment;
        await versions.IncrementAsync(assignment.TenantId, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask RemoveGroupAsync(
        GroupRoleAssignment assignment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        _groups.TryRemove((assignment.TenantId.Value, assignment.GroupId.Value, assignment.RoleId.Value), out _);
        await versions.IncrementAsync(assignment.TenantId, cancellationToken).ConfigureAwait(false);
    }
}
