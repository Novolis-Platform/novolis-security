using Microsoft.Extensions.DependencyInjection;
using Novolis.Security.Authentication;

namespace Novolis.Security.Authorization;

/// <summary>Default-deny authorization engine. Tenant context is always explicit.</summary>
public sealed class AuthorizationService(
    IGroupMembershipStore memberships,
    IRoleAssignmentStore assignments,
    IRoleProvider roles,
    IAuthorizationVersionStore versions,
    EffectiveAuthorizationCache cache,
    IAuthorizationEventSink events,
    TimeProvider time,
    IServiceProvider services,
    IIdentityStore? identities = null) : IAuthorizationService
{
    /// <inheritdoc />
    public async ValueTask<AuthorizationDecision> AuthorizeAsync(
        IdentityId identityId,
        TenantId tenantId,
        PermissionId permission,
        CancellationToken cancellationToken = default)
    {
        if (await IsDisabledAsync(identityId, cancellationToken).ConfigureAwait(false))
            return AuthorizationDecision.Deny("identity_disabled");

        var effective = await EvaluateAsync(identityId, tenantId, cancellationToken).ConfigureAwait(false);
        if (effective.Permissions.Contains(permission))
            return AuthorizationDecision.Allow();

        await ObserveAsync(
            AuthorizationEventTypes.AuthorizationDenied,
            tenantId,
            identityId,
            roleId: null,
            permission.Value,
            cancellationToken).ConfigureAwait(false);
        return AuthorizationDecision.Deny("missing_permission");
    }

    /// <inheritdoc />
    public async ValueTask<AuthorizationDecision> AuthorizeRoleAsync(
        IdentityId identityId,
        TenantId tenantId,
        RoleId roleId,
        CancellationToken cancellationToken = default)
    {
        if (await IsDisabledAsync(identityId, cancellationToken).ConfigureAwait(false))
            return AuthorizationDecision.Deny("identity_disabled");

        var effective = await EvaluateAsync(identityId, tenantId, cancellationToken).ConfigureAwait(false);
        if (effective.AssignedRoles.Contains(roleId))
            return AuthorizationDecision.Allow();

        await ObserveAsync(
            AuthorizationEventTypes.AuthorizationDenied,
            tenantId,
            identityId,
            roleId.Value,
            permissionId: null,
            cancellationToken).ConfigureAwait(false);
        return AuthorizationDecision.Deny("missing_role");
    }

    /// <inheritdoc />
    public async ValueTask<AuthorizationDecision> AuthorizeAsync<TResource, TAction>(
        IdentityId identityId,
        TenantId tenantId,
        TResource resource,
        TAction action,
        CancellationToken cancellationToken = default)
    {
        if (await IsDisabledAsync(identityId, cancellationToken).ConfigureAwait(false))
            return AuthorizationDecision.Deny("identity_disabled");

        var handler = services.GetService<IResourceAuthorizationHandler<TResource, TAction>>();
        if (handler is null)
            return AuthorizationDecision.Deny("missing_resource_handler");

        var effective = await EvaluateAsync(identityId, tenantId, cancellationToken).ConfigureAwait(false);
        var decision = await handler.AuthorizeAsync(
            identityId,
            tenantId,
            resource,
            action,
            effective.Permissions,
            cancellationToken).ConfigureAwait(false);
        if (decision.Succeeded)
            return decision;

        await ObserveAsync(
            AuthorizationEventTypes.AuthorizationDenied,
            tenantId,
            identityId,
            roleId: null,
            permissionId: null,
            cancellationToken).ConfigureAwait(false);
        return decision;
    }

    async ValueTask<EffectiveAuthorization> EvaluateAsync(
        IdentityId identityId,
        TenantId tenantId,
        CancellationToken cancellationToken)
    {
        var version = await versions.GetAsync(tenantId, cancellationToken).ConfigureAwait(false);
        if (cache.TryGet(tenantId, identityId, version, out var cached) && cached is not null)
            return cached;

        var assigned = new HashSet<RoleId>();
        foreach (var role in await assignments.FindIdentityRolesAsync(tenantId, identityId, cancellationToken)
                     .ConfigureAwait(false))
            assigned.Add(role);

        foreach (var groupId in await memberships.FindGroupsAsync(tenantId, identityId, cancellationToken)
                     .ConfigureAwait(false))
        {
            foreach (var role in await assignments.FindGroupRolesAsync(tenantId, groupId, cancellationToken)
                         .ConfigureAwait(false))
                assigned.Add(role);
        }

        var resolved = new Dictionary<string, RoleDefinition>(StringComparer.Ordinal);
        async ValueTask<RoleDefinition?> ResolveAsync(RoleId roleId)
        {
            if (resolved.TryGetValue(roleId.Value, out var known))
                return known;
            var definition = await roles.FindAsync(tenantId, roleId, cancellationToken).ConfigureAwait(false);
            if (definition is not null)
                resolved[roleId.Value] = definition;
            return definition;
        }

        async ValueTask ResolveGraphAsync(RoleId roleId)
        {
            var definition = await ResolveAsync(roleId).ConfigureAwait(false);
            if (definition is null)
                return;
            foreach (var included in definition.IncludedRoles)
            {
                if (!resolved.ContainsKey(included.Value))
                    await ResolveGraphAsync(included).ConfigureAwait(false);
            }
        }

        foreach (var roleId in assigned.ToArray())
            await ResolveGraphAsync(roleId).ConfigureAwait(false);

        var permissions = CompositeRoleGraph.ExpandPermissions(
            assigned,
            roleId => resolved.TryGetValue(roleId.Value, out var definition) ? definition : null);

        var effective = new EffectiveAuthorization(assigned, permissions);
        cache.Set(tenantId, identityId, version, effective);
        return effective;
    }

    async ValueTask<bool> IsDisabledAsync(IdentityId identityId, CancellationToken cancellationToken)
    {
        if (identities is null)
            return false;
        var identity = await identities.TryGetAsync(identityId, cancellationToken).ConfigureAwait(false);
        return identity is { Disabled: true };
    }

    async ValueTask ObserveAsync(
        string type,
        TenantId tenantId,
        IdentityId? identityId,
        string? roleId,
        string? permissionId,
        CancellationToken cancellationToken)
    {
        try
        {
            await events.RecordAsync(
                new AuthorizationSecurityEvent
                {
                    Utc = time.GetUtcNow(),
                    Type = type,
                    TenantId = tenantId,
                    IdentityId = identityId,
                    RoleId = roleId,
                    PermissionId = permissionId,
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Observation cannot change authorization state.
        }
    }
}
