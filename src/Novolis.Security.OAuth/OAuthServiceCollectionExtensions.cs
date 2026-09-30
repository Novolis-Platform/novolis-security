using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Novolis.Security.OAuth;

/// <summary>DI registration for the standards-oriented OAuth core.</summary>
public static class OAuthServiceCollectionExtensions
{
    /// <summary>
    /// Registers token issuance and safe in-memory stores.
    /// Call <c>AddNovolisOAuthStorage</c> to replace stores with durable adapters.
    /// </summary>
    public static IServiceCollection AddNovolisOAuth(
        this IServiceCollection services,
        Action<OAuthOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (configure is not null)
            services.Configure(configure);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ClientSecretHasher>();
        services.TryAddSingleton<IClientStore, InMemoryClientStore>();
        services.TryAddSingleton<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();
        services.TryAddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
        services.TryAddSingleton<ISigningKeyStore, InMemorySigningKeyStore>();
        services.TryAddSingleton<IKeyStore>(sp => sp.GetRequiredService<ISigningKeyStore>());
        services.TryAddSingleton<ICacheStore, InMemoryCacheStore>();
        services.TryAddSingleton<IEventStore>(_ => NoopEventStore.Instance);
        services.TryAddSingleton<SigningKeyRing>();
        services.TryAddSingleton<OAuthTokenService>();
        services.TryAddSingleton<ITokenService>(sp => sp.GetRequiredService<OAuthTokenService>());
        return services;
    }
}
