using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Novolis.Security.Authentication;

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
        services.TryAddSingleton<ICacheStore>(sp => new InMemoryCacheStore(sp.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton<IEventStore>(sp =>
        {
            var factory = sp.GetService<ILoggerFactory>();
            ILogger<LoggerEventStore> logger = factory is null
                ? NullLogger<LoggerEventStore>.Instance
                : factory.CreateLogger<LoggerEventStore>();
            return new LoggerEventStore(logger);
        });
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IIdentityRevocation, IdentityOAuthRevocation>());
        services.TryAddSingleton<SigningKeyRing>();
        services.TryAddSingleton<OAuthTokenService>();
        services.TryAddSingleton<ITokenService>(sp => sp.GetRequiredService<OAuthTokenService>());
        return services;
    }

    /// <summary>Replaces the default logger sink with a host delegate.</summary>
    public static IServiceCollection AddNovolisOAuthEvents(
        this IServiceCollection services,
        Func<SecurityEvent, CancellationToken, ValueTask> handler)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(handler);
        services.Replace(ServiceDescriptor.Singleton<IEventStore>(_ => new DelegateEventStore(handler)));
        return services;
    }
}
