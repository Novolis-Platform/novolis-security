using Microsoft.Extensions.DependencyInjection;
using Novolis.Security.Idp;
using Novolis.Storage.Abstractions;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class JsonStoreIdentityTests
{
    [Test]
    public async Task JsonStores_PasswordGrant_PersistsAndRotatesRefresh()
    {
        var root = Path.Combine(Path.GetTempPath(), "novolis-idp-json-" + Guid.CreateVersion7().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var services = new ServiceCollection();
            services.AddReferenceIdentity();
            services.AddJsonStores(root);
            await using var provider = services.BuildServiceProvider();

            var hasher = provider.GetRequiredService<Novolis.Security.PasswordHashing.PasswordHasher>();
            var accountId = AccountId.New();
            await provider.GetRequiredService<IClientStore>().UpsertAsync(new IdpClient
            {
                Id = Guid.CreateVersion7(),
                ClientId = "app",
                SecretHash = hasher.HashPassword("client-secret"),
                Confidential = true,
                AllowedGrantTypes = [IdpGrantTypes.Password, IdpGrantTypes.RefreshToken],
                AllowedScopes = ["api"],
                AllowedAudiences = ["novolis"],
            });
            await provider.GetRequiredService<IAccountStore>().UpsertAsync(new IdpAccount
            {
                Id = accountId.Value,
                PasswordHash = hasher.HashPassword("pw"),
                CreatedUtc = DateTimeOffset.UtcNow,
            });

            var tokens = provider.GetRequiredService<ITokenService>();
            var issued = await tokens.IssueAsync(new TokenIssueRequest
            {
                GrantType = IdpGrantTypes.Password,
                ClientId = "app",
                ClientSecret = "client-secret",
                AccountId = accountId,
                Password = "pw",
                Scope = "api",
            });
            await Assert.That(issued.Succeeded).IsTrue();
            await Assert.That(provider.GetRequiredService<IRepository<IdpRefreshToken>>().All().Any()).IsTrue();

            var rotated = await tokens.IssueAsync(new TokenIssueRequest
            {
                GrantType = IdpGrantTypes.RefreshToken,
                ClientId = "app",
                ClientSecret = "client-secret",
                RefreshToken = issued.RefreshToken,
            });
            await Assert.That(rotated.Succeeded).IsTrue();

            var replay = await tokens.IssueAsync(new TokenIssueRequest
            {
                GrantType = IdpGrantTypes.RefreshToken,
                ClientId = "app",
                ClientSecret = "client-secret",
                RefreshToken = issued.RefreshToken,
            });
            await Assert.That(replay.Error).IsEqualTo(IdpTokenErrors.InvalidGrant);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }
}
