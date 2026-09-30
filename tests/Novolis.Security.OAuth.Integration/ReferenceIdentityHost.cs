using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Novolis.Security.Authentication;
using Novolis.Security.Authentication.Storage;
using Novolis.Security.Authorization.Storage;
using Novolis.Security.OAuth;
using Novolis.Security.OAuth.Storage;
using Novolis.Security.PasswordHashing;
using Novolis.Storage.Abstractions;
using Novolis.Storage.Json;
using Novolis.Storage.Sqlite;

namespace Novolis.Security.Tests;

internal static class ReferenceIdentityHost
{
    internal static void FastArgon(PasswordHasherOptions o)
    {
        o.MemorySizeKiB = 32;
        o.Iterations = 1;
        o.DegreeOfParallelism = 1;
    }

    internal static IServiceCollection AddReferenceIdentity(this IServiceCollection services, Action<OAuthOptions>? configure = null)
    {
        services.AddLogging();
        services.Configure<PasswordHasherOptions>(FastArgon);
        services.AddMemoryCache();
        services.AddNovolisAuthentication();
        services.AddNovolisOAuth(o =>
        {
            o.Issuer = new Uri("https://accounts.test");
            o.IsDevelopment = true;
            o.AllowEphemeralSigningKey = true;
            configure?.Invoke(o);
        });
        services.Replace(ServiceDescriptor.Singleton<ICacheStore, MemoryCacheStore>());
        return services;
    }

    internal static IServiceCollection AddJsonStores(this IServiceCollection services, string rootPath)
    {
        services.AddStorage(b => b.AddJsonProvider(o =>
        {
            o.RootPath = rootPath;
            o.CreateIfMissing = true;
            o.UseProcessLock = false;
        }));
        services.AddNovolisOAuthStorage();
        return services;
    }

    internal static IServiceCollection AddSqliteStores(this IServiceCollection services, string connectionString)
    {
        services.AddStorage(b => b.AddSqliteProvider(o => o.ConnectionString = connectionString));
        services.AddNovolisOAuthStorage();
        return services;
    }

    /// <summary>
    /// Replaces in-memory identity and authorization stores with the configured repository provider.
    /// Call after <see cref="AddJsonStores"/> or <see cref="AddSqliteStores"/>, and after authorization services are registered.
    /// </summary>
    internal static IServiceCollection AddDurableIdentityStores(this IServiceCollection services)
    {
        services.AddNovolisAuthenticationStorage();
        services.AddNovolisAuthorizationStorage();
        return services;
    }

    internal static async Task SeedClientAsync(IServiceProvider services)
    {
        var hasher = services.GetRequiredService<ClientSecretHasher>();
        await services.GetRequiredService<IClientStore>().UpsertAsync(new OAuthClient
        {
            Id = Guid.NewGuid(),
            ClientId = "space-game-web",
            ClientType = OAuthClientType.Confidential,
            SecretHash = hasher.Hash("client-secret"),
            AllowedGrantTypes = [OAuthGrantTypes.AuthorizationCode, OAuthGrantTypes.RefreshToken, OAuthGrantTypes.ClientCredentials],
            AllowedScopes = ["game"],
            AllowedAudiences = ["space-game-api"],
            AllowedRedirectUris = ["https://game.example/callback"],
        });
    }
}
