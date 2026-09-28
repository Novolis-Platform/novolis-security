using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Novolis.Security.Idp;
using Novolis.Security.Idp.Storage;
using Novolis.Security.PasswordHashing;
using Novolis.Storage.Abstractions;
using Novolis.Storage.Json;
using Novolis.Storage.Sqlite;

namespace Novolis.Security.Tests;

/// <summary>
/// Reference wiring for a <em>library</em> identity host — not a full IDP executable.
/// A product IDP would add TLS, a separate identifier directory, PEM custody, and edge IP limits.
/// </summary>
/// <remarks>
/// JSON (file-per-entity) and SQLite both go through <c>AddNovolisIdpStorage</c>.
/// Cache: this adapter wraps <see cref="IMemoryCache"/>; a farm replaces <see cref="ICacheStore"/> with Redis INCR/SETNX.
/// Events: default is <see cref="NoopEventStore"/>; swap <see cref="IEventStore"/> to observe grants.
///
/// SQLite cannot persist <see cref="IdpClient"/> today — <c>List&lt;string&gt;</c> has no affinity in
/// <c>Novolis.Storage.Sqlite</c>. JSON can. Do not pretend otherwise.
/// </remarks>
internal static class ReferenceIdentityHost
{
    internal static void FastArgon(PasswordHasherOptions o)
    {
        o.MemorySizeKiB = 32;
        o.Iterations = 1;
        o.DegreeOfParallelism = 1;
    }

    internal static IServiceCollection AddReferenceIdentity(this IServiceCollection services, Action<IdpOptions>? configure = null)
    {
        services.AddLogging();
        services.Configure<PasswordHasherOptions>(FastArgon);
        services.AddMemoryCache();
        services.AddNovolisIdp(o =>
        {
            o.Issuer = "https://idp.test";
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
        services.AddNovolisIdpStorage();
        return services;
    }

    internal static IServiceCollection AddSqliteStores(this IServiceCollection services, string connectionString)
    {
        services.AddStorage(b => b.AddSqliteProvider(o => o.ConnectionString = connectionString));
        services.AddNovolisIdpStorage();
        return services;
    }

    internal static async Task SeedAsync(IServiceProvider services, string password = "pw")
    {
        var hasher = services.GetRequiredService<PasswordHasher>();
        await services.GetRequiredService<IClientStore>().UpsertAsync(new IdpClient
        {
            Id = Guid.CreateVersion7(),
            ClientId = "app",
            SecretHash = hasher.HashPassword("client-secret"),
            Confidential = true,
            AllowedGrantTypes = [IdpGrantTypes.Password, IdpGrantTypes.RefreshToken, IdpGrantTypes.ClientCredentials],
            AllowedScopes = ["api"],
            AllowedAudiences = ["novolis"],
        });
        await services.GetRequiredService<IAccountStore>().UpsertAsync(new IdpAccount
        {
            Id = AccountId.New().Value,
            PasswordHash = hasher.HashPassword(password),
            CreatedUtc = DateTimeOffset.UtcNow,
        });
    }
}

/// <summary>
/// Single-node <see cref="IMemoryCache"/> adapter. Not a farm lock — increments and leases take a process lock.
/// </summary>
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
