using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Novolis.Security.Authorization;

/// <summary>Registers the tenant-scoped authorization engine and in-memory stores.</summary>
public static class AuthorizationServiceCollectionExtensions
{
    /// <summary>Adds authorization services. ASP.NET hosts should also call the AspNetCore package.</summary>
    public static IServiceCollection AddNovolisAuthorization(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(sp =>
        {
            var catalog = new PermissionCatalog();
            foreach (var registration in sp.GetServices<IPermissionRegistration>())
                catalog.Add(registration.Permission);
            return catalog;
        });
        services.TryAddSingleton<IPermissionCatalog>(sp => sp.GetRequiredService<PermissionCatalog>());
        services.TryAddSingleton(sp =>
        {
            var registry = new BuiltInRoleRegistry();
            foreach (var registration in sp.GetServices<IBuiltInRoleRegistration>())
                registration.Apply(registry);
            return registry;
        });
        services.TryAddSingleton<IAuthorizationVersionStore, InMemoryAuthorizationVersionStore>();
        services.TryAddSingleton<EffectiveAuthorizationCache>();
        services.TryAddSingleton<IGroupStore, InMemoryGroupStore>();
        services.TryAddSingleton<IGroupMembershipStore, InMemoryGroupMembershipStore>();
        services.TryAddSingleton<InMemoryRoleStore>();
        services.TryAddSingleton<IRoleStore>(sp => new ValidatingRoleStore(
            sp.GetRequiredService<InMemoryRoleStore>(),
            sp.GetRequiredService<IPermissionCatalog>(),
            sp.GetRequiredService<BuiltInRoleRegistry>(),
            sp.GetRequiredService<IAuthorizationVersionStore>()));
        services.TryAddSingleton<IRoleAssignmentStore, InMemoryRoleAssignmentStore>();
        services.TryAddSingleton<BuiltInRoleProvider>();
        services.TryAddSingleton<StoredRoleProvider>();
        services.TryAddSingleton<IRoleProvider, CompositeRoleProvider>();
        services.TryAddSingleton<IAuthorizationEventSink>(sp =>
        {
            var factory = sp.GetService<ILoggerFactory>();
            ILogger<LoggerAuthorizationEventSink> logger = factory is null
                ? NullLogger<LoggerAuthorizationEventSink>.Instance
                : factory.CreateLogger<LoggerAuthorizationEventSink>();
            return new LoggerAuthorizationEventSink(logger);
        });
        services.TryAddSingleton<AuthorizationService>();
        services.TryAddSingleton<IAuthorizationService>(sp => sp.GetRequiredService<AuthorizationService>());
        return services;
    }

    /// <summary>Registers a permission the application understands.</summary>
    public static IServiceCollection AddPermission<TPermission>(this IServiceCollection services)
        where TPermission : IPermission
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<IPermissionRegistration>(new PermissionRegistration<TPermission>());
        return services;
    }

    /// <summary>Registers a built-in role definition.</summary>
    public static IServiceCollection AddBuiltInRole<TRole>(this IServiceCollection services)
        where TRole : IBuiltInRole
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<IBuiltInRoleRegistration>(new BuiltInRoleRegistration<TRole>());
        return services;
    }
}
