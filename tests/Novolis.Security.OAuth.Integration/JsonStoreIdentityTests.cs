using Microsoft.Extensions.DependencyInjection;
using Novolis.Security.OAuth;
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
            var accountId = CredentialReference.New();
            await provider.GetRequiredService<IClientStore>().UpsertAsync(new OAuthClient
            {
                Id = Guid.CreateVersion7(),
                ClientId = "app",
                SecretHash = hasher.HashPassword("client-secret"),
                Confidential = true,
                AllowedGrantTypes = [OAuthGrantTypes.Password, OAuthGrantTypes.RefreshToken],
                AllowedScopes = ["api"],
                AllowedAudiences = ["novolis"],
            });
            await provider.GetRequiredService<ICredentialStore>().UpsertAsync(new CredentialRecord
            {
                Id = accountId.Value,
                PasswordHash = hasher.HashPassword("pw"),
                CreatedUtc = DateTimeOffset.UtcNow,
            });

            var tokens = provider.GetRequiredService<ITokenService>();
            var issued = await tokens.IssueAsync(new TokenIssueRequest
            {
                GrantType = OAuthGrantTypes.Password,
                ClientId = "app",
                ClientSecret = "client-secret",
                CredentialReference = accountId,
                Password = "pw",
                Scope = "api",
            });
            await Assert.That(issued.Succeeded).IsTrue();
            await Assert.That(provider.GetRequiredService<IRepository<RefreshTokenRecord>>().All().Any()).IsTrue();

            var rotated = await tokens.IssueAsync(new TokenIssueRequest
            {
                GrantType = OAuthGrantTypes.RefreshToken,
                ClientId = "app",
                ClientSecret = "client-secret",
                RefreshToken = issued.RefreshToken,
            });
            await Assert.That(rotated.Succeeded).IsTrue();

            var replay = await tokens.IssueAsync(new TokenIssueRequest
            {
                GrantType = OAuthGrantTypes.RefreshToken,
                ClientId = "app",
                ClientSecret = "client-secret",
                RefreshToken = issued.RefreshToken,
            });
            await Assert.That(replay.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }
}
