using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Novolis.Security.OAuth.Storage;

/// <summary>Binds OAuth stores to primitive <c>IRepository&lt;T&gt;</c> rows. Call after <c>AddNovolisOAuth</c> and <c>AddStorage</c>.</summary>
public static class OAuthStorageServiceCollectionExtensions
{
    /// <summary>Replaces in-memory OAuth stores with repository adapters.</summary>
    public static IServiceCollection AddNovolisOAuthStorage(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Replace(ServiceDescriptor.Singleton<IClientStore, RepositoryClientStore>());
        services.Replace(ServiceDescriptor.Singleton<IAuthorizationCodeStore, RepositoryAuthorizationCodeStore>());
        services.Replace(ServiceDescriptor.Singleton<IRefreshTokenStore, RepositoryRefreshTokenStore>());
        services.Replace(ServiceDescriptor.Singleton<ISigningKeyStore, RepositorySigningKeyStore>());
        services.Replace(ServiceDescriptor.Singleton<IKeyStore>(sp => sp.GetRequiredService<ISigningKeyStore>()));
        return services;
    }
}
