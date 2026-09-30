using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace Novolis.Security.Authorization.AspNetCore;

/// <summary>Minimal API metadata extensions.</summary>
public static class AuthorizationEndpointConventionBuilderExtensions
{
    /// <summary>Requires a compile-time permission without embedding authorization logic.</summary>
    public static TBuilder RequirePermission<TPermission, TBuilder>(this TBuilder builder)
        where TPermission : IPermission
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.WithMetadata(new RequirePermissionAttribute<TPermission>());
        builder.RequireAuthorization();
        return builder;
    }

    /// <summary>Requires a compile-time assigned role without embedding authorization logic.</summary>
    public static TBuilder RequireRole<TRole, TBuilder>(this TBuilder builder)
        where TRole : IRole
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.WithMetadata(new RequireRoleAttribute<TRole>());
        builder.RequireAuthorization();
        return builder;
    }

    /// <summary>Requires a compile-time permission on a minimal API endpoint.</summary>
    public static RouteHandlerBuilder RequirePermission<TPermission>(this RouteHandlerBuilder builder)
        where TPermission : IPermission =>
        builder.RequirePermission<TPermission, RouteHandlerBuilder>();

    /// <summary>Requires a compile-time assigned role on a minimal API endpoint.</summary>
    public static RouteHandlerBuilder RequireRole<TRole>(this RouteHandlerBuilder builder)
        where TRole : IRole =>
        builder.RequireRole<TRole, RouteHandlerBuilder>();
}
