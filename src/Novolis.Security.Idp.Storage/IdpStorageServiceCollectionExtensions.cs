using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Novolis.Security.Idp;

namespace Novolis.Security.Idp.Storage;

/// <summary>Binds identity stores to <c>IRepository&lt;T&gt;</c>. Call after <c>AddNovolisIdp</c> and <c>AddStorage</c>.</summary>
public static class IdpStorageServiceCollectionExtensions
{
    /// <summary>Replaces in-memory identity stores with repository adapters.</summary>
    public static IServiceCollection AddNovolisIdpStorage(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Replace(ServiceDescriptor.Singleton<IAccountStore, RepositoryAccountStore>());
        services.Replace(ServiceDescriptor.Singleton<IClientStore, RepositoryClientStore>());
        services.Replace(ServiceDescriptor.Singleton<IRefreshTokenStore, RepositoryRefreshTokenStore>());
        services.Replace(ServiceDescriptor.Singleton<ISigningKeyStore, RepositorySigningKeyStore>());
        services.Replace(ServiceDescriptor.Singleton<IKeyStore>(sp => sp.GetRequiredService<ISigningKeyStore>()));
        return services;
    }
}
