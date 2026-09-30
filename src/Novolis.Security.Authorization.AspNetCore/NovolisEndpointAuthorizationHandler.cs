using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using CoreAuthorization = Novolis.Security.Authorization.IAuthorizationService;

namespace Novolis.Security.Authorization.AspNetCore;

/// <summary>Translates endpoint metadata into the core authorization engine.</summary>
public sealed class NovolisEndpointAuthorizationHandler(
    CoreAuthorization authorization,
    ITenantContextAccessor tenants) : IAuthorizationHandler
{
    /// <inheritdoc />
    public async Task HandleAsync(AuthorizationHandlerContext context)
    {
        if (context.Resource is not HttpContext http)
            return;

        var endpoint = http.GetEndpoint();
        if (endpoint is null)
            return;

        var permissions = endpoint.Metadata.GetOrderedMetadata<IPermissionRequirementMetadata>();
        var roles = endpoint.Metadata.GetOrderedMetadata<IRoleRequirementMetadata>();
        if (permissions.Count == 0 && roles.Count == 0)
            return;

        var identityId = context.User.GetNovolisIdentityId();
        var tenantId = tenants.TenantId;
        if (identityId is null || tenantId is null)
        {
            context.Fail();
            return;
        }

        foreach (var permission in permissions)
        {
            var decision = await authorization.AuthorizeAsync(
                identityId.Value,
                tenantId.Value,
                permission.Permission,
                http.RequestAborted).ConfigureAwait(false);
            if (!decision.Succeeded)
            {
                context.Fail();
                return;
            }
        }

        foreach (var role in roles)
        {
            var decision = await authorization.AuthorizeRoleAsync(
                identityId.Value,
                tenantId.Value,
                role.Role,
                http.RequestAborted).ConfigureAwait(false);
            if (!decision.Succeeded)
            {
                context.Fail();
                return;
            }
        }
    }
}
