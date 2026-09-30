using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Novolis.Security.Authentication;

namespace Novolis.Security.Authorization.AspNetCore;

/// <summary>ASP.NET Core authorization composition.</summary>
public static class AuthorizationAspNetCoreServiceCollectionExtensions
{
    /// <summary>Adds the authorization engine, tenant accessor, and endpoint metadata handler.</summary>
    public static IServiceCollection AddNovolisAuthorization(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        AuthorizationServiceCollectionExtensions.AddNovolisAuthorization(services);
        services.AddAuthorization();
        services.TryAddScoped<ITenantContextAccessor, TenantContextAccessor>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<Microsoft.AspNetCore.Authorization.IAuthorizationHandler, NovolisEndpointAuthorizationHandler>());
        return services;
    }

    /// <summary>Fluent continuation from <see cref="NovolisSecurityBuilder"/>.</summary>
    public static NovolisSecurityBuilder AddNovolisAuthorization(this NovolisSecurityBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddNovolisAuthorization();
        return builder;
    }
}
