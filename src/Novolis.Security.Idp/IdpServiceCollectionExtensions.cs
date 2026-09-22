using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Novolis.Security.PasswordHashing;

namespace Novolis.Security.Idp;

/// <summary>DI registration for the limited IDP (in-memory stores by default).</summary>
public static class IdpServiceCollectionExtensions
{
    /// <summary>
    /// Registers token issuance, Argon2id hashing, and in-memory stores.
    /// Call <c>AddNovolisIdpStorage</c> afterwards to replace stores with <c>IRepository&lt;T&gt;</c>.
    /// </summary>
    public static IServiceCollection AddNovolisIdp(this IServiceCollection services, Action<IdpOptions>? configure = null)
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
        services.TryAddSingleton<IAccountStore, InMemoryAccountStore>();
        services.TryAddSingleton<IClientStore, InMemoryClientStore>();
        services.TryAddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
        services.TryAddSingleton<ISigningKeyStore, InMemorySigningKeyStore>();
        services.TryAddSingleton<SigningKeyRing>();
        services.TryAddSingleton<IdpTokenService>();
        services.TryAddSingleton<IIdpTokenService>(sp => sp.GetRequiredService<IdpTokenService>());
        return services;
    }
}
