using Microsoft.Extensions.DependencyInjection;
using Novolis.Security.OAuth;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class SqliteStoreIdentityTests
{
    [Test]
    public async Task Sqlite_PersistsAccountAndRefresh_ScalarEntities()
    {
        var db = Path.Combine(Path.GetTempPath(), "novolis-idp-" + Guid.CreateVersion7().ToString("N") + ".db");
        try
        {
            var services = new ServiceCollection();
            services.AddReferenceIdentity();
            services.AddSqliteStores("Data Source=" + db + ";Pooling=False");
            await using (var provider = services.BuildServiceProvider())
            {
                var hasher = provider.GetRequiredService<Novolis.Security.PasswordHashing.PasswordHasher>();
                var account = new CredentialRecord
                {
                    Id = CredentialReference.New().Value,
                    PasswordHash = hasher.HashPassword("pw"),
                    CreatedUtc = DateTimeOffset.UtcNow,
                };
                await provider.GetRequiredService<ICredentialStore>().UpsertAsync(account);
                var loaded = await provider.GetRequiredService<ICredentialStore>().TryGetAsync(new CredentialReference(account.Id));
                await Assert.That(loaded).IsNotNull();
                await Assert.That(loaded!.PasswordHash).IsEqualTo(account.PasswordHash);

                var refresh = new RefreshTokenRecord
                {
                    Id = Guid.CreateVersion7(),
                    FamilyId = Guid.CreateVersion7(),
                    CredentialReference = account.Id,
                    ClientId = Guid.CreateVersion7(),
                    SecretHash = "hash",
                    Scope = "api",
                    ExpiresUtc = DateTimeOffset.UtcNow.AddDays(1),
                };
                await provider.GetRequiredService<IRefreshTokenStore>().UpsertAsync(refresh);
                var found = await provider.GetRequiredService<IRefreshTokenStore>().TryGetAsync(refresh.Id);
                await Assert.That(found).IsNotNull();
            }
        }
        finally
        {
            TryDelete(db);
        }
    }

    [Test]
    public async Task Sqlite_CannotMapOAuthClientListProperties()
    {
        var db = Path.Combine(Path.GetTempPath(), "novolis-idp-client-" + Guid.CreateVersion7().ToString("N") + ".db");
        try
        {
            var services = new ServiceCollection();
            services.AddReferenceIdentity();
            services.AddSqliteStores("Data Source=" + db + ";Pooling=False");
            await using (var provider = services.BuildServiceProvider())
            {
                Exception? caught = null;
                try
                {
                    _ = provider.GetRequiredService<IClientStore>();
                }
                catch (Exception ex)
                {
                    caught = ex;
                }

                await Assert.That(caught).IsNotNull();
                await Assert.That(caught!.GetBaseException() is KeyNotFoundException).IsTrue();
            }
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
