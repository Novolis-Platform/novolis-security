using Microsoft.Extensions.DependencyInjection;
using Novolis.Security.OAuth;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class SqliteStoreIdentityTests
{
    [Test]
    public async Task Sqlite_PersistsPackedClients_AndAtomicRefreshRotation()
    {
        var db = Path.Combine(Path.GetTempPath(), "novolis-oauth-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            var services = new ServiceCollection();
            services.AddReferenceIdentity();
            services.AddSqliteStores("Data Source=" + db + ";Pooling=False");
            await using var provider = services.BuildServiceProvider();
            await ReferenceIdentityHost.SeedClientAsync(provider);
            var client = await provider.GetRequiredService<IClientStore>().FindByClientIdAsync("space-game-web");
            await Assert.That(client).IsNotNull();
            await Assert.That(client!.AllowedGrantTypes).Contains(OAuthGrantTypes.AuthorizationCode);

            var store = provider.GetRequiredService<IRefreshTokenStore>();
            var current = new RefreshTokenRecord
            {
                Id = Guid.NewGuid(),
                FamilyId = Guid.NewGuid(),
                IdentityId = Novolis.Security.Authentication.IdentityId.New(),
                ClientId = client.Id,
                ClientPublicId = client.ClientId,
                SecretHash = Convert.ToBase64String(new byte[64]),
                Scope = "game",
                Audience = "space-game-api",
                CreatedUtc = DateTimeOffset.UtcNow,
                ExpiresUtc = DateTimeOffset.UtcNow.AddDays(1),
            };
            await store.UpsertAsync(current);
            var replacement = new RefreshTokenRecord
            {
                Id = Guid.NewGuid(),
                FamilyId = current.FamilyId,
                IdentityId = current.IdentityId,
                ClientId = current.ClientId,
                ClientPublicId = current.ClientPublicId,
                SecretHash = Convert.ToBase64String(new byte[64]),
                Scope = current.Scope,
                Audience = current.Audience,
                CreatedUtc = DateTimeOffset.UtcNow,
                ExpiresUtc = DateTimeOffset.UtcNow.AddDays(1),
            };
            var rotated = await store.TryRotateAsync(current.Id, replacement, DateTimeOffset.UtcNow);
            await Assert.That(rotated.Succeeded).IsTrue();
            var replay = await store.TryRotateAsync(current.Id, replacement, DateTimeOffset.UtcNow);
            await Assert.That(replay.WasReplayed).IsTrue();
        }
        finally
        {
            TryDelete(db);
        }
    }

    static void TryDelete(string db)
    {
        try
        {
            if (File.Exists(db))
                File.Delete(db);
        }
        catch (IOException)
        {
            // SqliteClient may still hold the file until process teardown.
        }
    }
}
