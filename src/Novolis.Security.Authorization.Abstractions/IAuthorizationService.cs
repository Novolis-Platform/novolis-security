using Novolis.Security.Authentication;

namespace Novolis.Security.Authorization;

/// <summary>Tenant-scoped authorization engine independent of ASP.NET Core.</summary>
public interface IAuthorizationService
{
    /// <summary>Allows the operation when the identity has the permission in the tenant.</summary>
    ValueTask<AuthorizationDecision> AuthorizeAsync(
        IdentityId identityId,
        TenantId tenantId,
        PermissionId permission,
        CancellationToken cancellationToken = default);

    /// <summary>Allows the operation when the identity is assigned the role in the tenant.</summary>
    ValueTask<AuthorizationDecision> AuthorizeRoleAsync(
        IdentityId identityId,
        TenantId tenantId,
        RoleId roleId,
        CancellationToken cancellationToken = default);

    /// <summary>Combines permission evaluation with an application resource handler.</summary>
    ValueTask<AuthorizationDecision> AuthorizeAsync<TResource, TAction>(
        IdentityId identityId,
        TenantId tenantId,
        TResource resource,
        TAction action,
        CancellationToken cancellationToken = default);
}
