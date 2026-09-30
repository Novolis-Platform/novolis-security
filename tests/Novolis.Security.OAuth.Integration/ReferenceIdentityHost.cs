using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Novolis.Security.Authentication;
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

internal sealed class MemoryCacheStore(IMemoryCache cache) : ICacheStore
{
    readonly object _gate = new();

    public ValueTask<long> IncrementAsync(string key, TimeSpan ttl, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            var entry = Read(key, now);
            entry = new Entry(entry.Value + 1, now + ttl);
            Write(key, entry);
            return ValueTask.FromResult(entry.Value);
        }
    }

    public ValueTask<long> GetAsync(string key, CancellationToken ct = default)
    {
        lock (_gate)
            return ValueTask.FromResult(Read(key, DateTimeOffset.UtcNow).Value);
    }

    public ValueTask<bool> TryCreateAsync(string key, TimeSpan ttl, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            if (Read(key, now).Value > 0)
                return ValueTask.FromResult(false);
            Write(key, new Entry(1, now + ttl));
            return ValueTask.FromResult(true);
        }
    }

    Entry Read(string key, DateTimeOffset now)
    {
        if (cache.TryGetValue(key, out Entry entry) && entry.ExpiresUtc > now)
            return entry;
        return default;
    }

    void Write(string key, Entry entry) =>
        cache.Set(key, entry, new MemoryCacheEntryOptions { AbsoluteExpiration = entry.ExpiresUtc });

    readonly record struct Entry(long Value, DateTimeOffset ExpiresUtc);
}
