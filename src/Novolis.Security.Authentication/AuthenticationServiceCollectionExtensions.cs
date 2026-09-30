using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Novolis.Security.PasswordHashing;

namespace Novolis.Security.Authentication;

/// <summary>Registers the high-level authentication façade and safe development stores.</summary>
public static class AuthenticationServiceCollectionExtensions
{
    /// <summary>Adds identity resolution, credential verification, and browser sessions.</summary>
    public static IServiceCollection AddNovolisAuthentication(
        this IServiceCollection services,
        Action<AuthenticationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (configure is not null)
            services.Configure(configure);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(sp =>
        {
            var options = sp.GetService<IOptions<PasswordHasherOptions>>()
                ?? Options.Create(new PasswordHasherOptions());
            return new PasswordHasher(options);
        });
        services.TryAddSingleton<IIdentityStore, InMemoryIdentityStore>();
        services.TryAddSingleton<ICredentialStore, InMemoryCredentialStore>();
        services.TryAddSingleton<IAuthenticationSessionStore, InMemoryAuthenticationSessionStore>();
        services.TryAddSingleton<ICacheStore>(sp => new InMemoryCacheStore(sp.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton<IMfaProvider>(_ => NoopMfaProvider.Instance);
        services.TryAddSingleton<IAuthenticationEventSink>(_ => NoopAuthenticationEventSink.Instance);
        services.TryAddSingleton<AuthenticationService>();
        services.TryAddSingleton<IAuthenticationService>(sp =>
            sp.GetRequiredService<AuthenticationService>());
        return services;
    }
}
