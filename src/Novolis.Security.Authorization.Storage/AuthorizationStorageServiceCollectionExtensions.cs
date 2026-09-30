using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authorization.Storage;

/// <summary>Binds authorization stores to primitive repository rows.</summary>
public static class AuthorizationStorageServiceCollectionExtensions
{
    /// <summary>Replaces in-memory authorization stores with repository adapters.</summary>
    public static IServiceCollection AddNovolisAuthorizationStorage(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Replace(ServiceDescriptor.Singleton<IAuthorizationVersionStore, RepositoryAuthorizationVersionStore>());
        services.Replace(ServiceDescriptor.Singleton<IGroupStore, RepositoryGroupStore>());
        services.Replace(ServiceDescriptor.Singleton<IGroupMembershipStore, RepositoryGroupMembershipStore>());
        services.Replace(ServiceDescriptor.Singleton<IRoleStore>(sp => new ValidatingRoleStore(
            new RepositoryRoleStore(sp.GetRequiredService<IRepository<StoredRole>>()),
            sp.GetRequiredService<IPermissionCatalog>(),
            sp.GetRequiredService<BuiltInRoleRegistry>(),
            sp.GetRequiredService<IAuthorizationVersionStore>())));
        services.Replace(ServiceDescriptor.Singleton<IRoleAssignmentStore, RepositoryRoleAssignmentStore>());
        return services;
    }
}
