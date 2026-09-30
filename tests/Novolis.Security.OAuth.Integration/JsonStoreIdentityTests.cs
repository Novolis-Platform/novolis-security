using Microsoft.Extensions.DependencyInjection;
using Novolis.Security.OAuth;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class JsonStoreIdentityTests
{
    [Test]
    public async Task Json_PersistsClientAndRefresh()
    {
        var root = Path.Combine(Path.GetTempPath(), "novolis-oauth-json-" + Guid.NewGuid().ToString("N"));
        try
        {
            var services = new ServiceCollection();
            services.AddReferenceIdentity();
            services.AddJsonStores(root);
            await using var provider = services.BuildServiceProvider();
            await ReferenceIdentityHost.SeedClientAsync(provider);
            var loaded = await provider.GetRequiredService<IClientStore>().FindByClientIdAsync("space-game-web");
            await Assert.That(loaded).IsNotNull();
            await Assert.That(loaded!.AllowedRedirectUris[0]).IsEqualTo("https://game.example/callback");

            var refresh = new RefreshTokenRecord
            {
                Id = Guid.NewGuid(),
                FamilyId = Guid.NewGuid(),
                IdentityId = Novolis.Security.Authentication.IdentityId.New(),
                ClientId = loaded.Id,
                ClientPublicId = loaded.ClientId,
                SecretHash = Convert.ToBase64String(new byte[64]),
                Scope = "game",
                Audience = "space-game-api",
                CreatedUtc = DateTimeOffset.UtcNow,
                ExpiresUtc = DateTimeOffset.UtcNow.AddDays(1),
            };
            await provider.GetRequiredService<IRefreshTokenStore>().UpsertAsync(refresh);
            var found = await provider.GetRequiredService<IRefreshTokenStore>().TryGetAsync(refresh.Id);
            await Assert.That(found).IsNotNull();
            await Assert.That(found!.Audience).IsEqualTo("space-game-api");
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }
}
