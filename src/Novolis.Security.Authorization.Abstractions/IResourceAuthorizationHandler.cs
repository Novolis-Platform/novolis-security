using Novolis.Security.Authentication;

namespace Novolis.Security.Authorization;

/// <summary>Application-specific resource rule evaluated after effective permissions are known.</summary>
public interface IResourceAuthorizationHandler<TResource, TAction>
{
    /// <summary>Evaluates resource-specific rules. Returning deny fails closed.</summary>
    ValueTask<AuthorizationDecision> AuthorizeAsync(
        IdentityId identityId,
        TenantId tenantId,
        TResource resource,
        TAction action,
        IReadOnlySet<PermissionId> effectivePermissions,
        CancellationToken cancellationToken = default);
}
