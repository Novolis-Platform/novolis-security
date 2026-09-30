using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Novolis.Security.PasswordHashing;

namespace Novolis.Security.OAuth;

/// <summary>DI registration for identity / authentication (in-memory stores by default).</summary>
public static class OAuthServiceCollectionExtensions
{
    /// <summary>
    /// Registers token issuance, Argon2id hashing, and in-memory stores.
    /// Call <c>AddNovolisOAuthStorage</c> afterwards to replace stores with <c>IRepository&lt;T&gt;</c>.
    /// </summary>
    public static IServiceCollection AddNovolisOAuth(this IServiceCollection services, Action<OAuthOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (configure is not null)
            services.Configure(configure);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(sp =>
        {
            var options = sp.GetService<IOptions<PasswordHasherOptions>>() ?? Options.Create(new PasswordHasherOptions());
            return new PasswordHasher(options);
        });
        services.TryAddSingleton<ICredentialStore, InMemoryAccountStore>();
        services.TryAddSingleton<IClientStore, InMemoryClientStore>();
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
