using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Novolis.Security.Idp;

namespace Novolis.Security.Idp.Storage;

/// <summary>Binds IDP stores to <c>IRepository&lt;T&gt;</c>. Call after <c>AddNovolisIdp</c> and <c>AddStorage</c>.</summary>
public static class IdpStorageServiceCollectionExtensions
{
    /// <summary>Replaces in-memory IDP stores with repository adapters.</summary>
    public static IServiceCollection AddNovolisIdpStorage(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Replace(ServiceDescriptor.Singleton<IAccountStore, RepositoryAccountStore>());
        services.Replace(ServiceDescriptor.Singleton<IClientStore, RepositoryClientStore>());
        services.Replace(ServiceDescriptor.Singleton<IRefreshTokenStore, RepositoryRefreshTokenStore>());
        services.Replace(ServiceDescriptor.Singleton<ISigningKeyStore, RepositorySigningKeyStore>());
        return services;
    }
}
