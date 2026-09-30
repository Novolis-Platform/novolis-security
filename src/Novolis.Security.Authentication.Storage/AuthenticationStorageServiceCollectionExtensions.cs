using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Novolis.Security.Authentication.Storage;

/// <summary>Binds authentication stores to primitive repository rows.</summary>
public static class AuthenticationStorageServiceCollectionExtensions
{
    /// <summary>Replaces in-memory identity, credential, and session stores.</summary>
    public static IServiceCollection AddNovolisAuthenticationStorage(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Replace(ServiceDescriptor.Singleton<IIdentityStore, RepositoryIdentityStore>());
        services.Replace(ServiceDescriptor.Singleton<ICredentialStore, RepositoryCredentialStore>());
        services.Replace(ServiceDescriptor.Singleton<IAuthenticationSessionStore, RepositoryAuthenticationSessionStore>());
        return services;
    }
}
