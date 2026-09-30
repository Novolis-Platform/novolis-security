using Novolis.Security.Authentication;
using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authorization.Storage;

/// <summary>Repository adapter for role assignments.</summary>
public sealed class RepositoryRoleAssignmentStore(
    IRepository<StoredRoleAssignment> repository,
    IAuthorizationVersionStore versions) : IRoleAssignmentStore
{
    /// <inheritdoc />
    public ValueTask<IReadOnlyList<RoleId>> FindIdentityRolesAsync(
        TenantId tenantId,
        IdentityId identityId,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<RoleId> matches = repository.All()
            .Where(row => row.TenantId == tenantId.Value && row.IdentityId == identityId.Value && row.GroupId == Guid.Empty)
            .Select(row => new RoleId(row.RoleId))
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
        IReadOnlyList<RoleId> matches = repository.All()
            .Where(row => row.TenantId == tenantId.Value && row.GroupId == groupId.Value && row.IdentityId == Guid.Empty)
            .Select(row => new RoleId(row.RoleId))
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
        await repository.UpsertAsync(
            new StoredRoleAssignment
            {
                Id = Guid.NewGuid(),
                TenantId = assignment.TenantId.Value,
                IdentityId = assignment.IdentityId.Value,
                RoleId = assignment.RoleId.Value,
            },
            cancellationToken).ConfigureAwait(false);
        await versions.IncrementAsync(assignment.TenantId, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask RemoveIdentityAsync(
        IdentityRoleAssignment assignment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        foreach (var row in repository.All().Where(r =>
                     r.TenantId == assignment.TenantId.Value
                     && r.IdentityId == assignment.IdentityId.Value
                     && r.GroupId == Guid.Empty
                     && string.Equals(r.RoleId, assignment.RoleId.Value, StringComparison.Ordinal)))
            await repository.DeleteAsync(row.Id, cancellationToken).ConfigureAwait(false);
        await versions.IncrementAsync(assignment.TenantId, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask AssignGroupAsync(
        GroupRoleAssignment assignment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        await repository.UpsertAsync(
            new StoredRoleAssignment
            {
                Id = Guid.NewGuid(),
                TenantId = assignment.TenantId.Value,
                GroupId = assignment.GroupId.Value,
                RoleId = assignment.RoleId.Value,
            },
            cancellationToken).ConfigureAwait(false);
        await versions.IncrementAsync(assignment.TenantId, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask RemoveGroupAsync(
        GroupRoleAssignment assignment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        foreach (var row in repository.All().Where(r =>
                     r.TenantId == assignment.TenantId.Value
                     && r.GroupId == assignment.GroupId.Value
                     && r.IdentityId == Guid.Empty
                     && string.Equals(r.RoleId, assignment.RoleId.Value, StringComparison.Ordinal)))
            await repository.DeleteAsync(row.Id, cancellationToken).ConfigureAwait(false);
        await versions.IncrementAsync(assignment.TenantId, cancellationToken).ConfigureAwait(false);
    }
}
