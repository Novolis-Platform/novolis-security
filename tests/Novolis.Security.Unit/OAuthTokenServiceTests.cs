using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Novolis.Security.OAuth;
using Novolis.Security.OAuth.AspNetCore;
using Novolis.Security.OAuth.Storage;
using Novolis.Security.PasswordHashing;
using Novolis.Storage.Abstractions;
using Novolis.Storage.InMemory;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class OAuthTokenServiceTests
{
    [Test]
    public async Task CredentialRecord_HasNoIdentifierFields()
    {
        var names = typeof(CredentialRecord).GetProperties().Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        string[] forbidden = ["Email", "Username", "UserName", "Handle", "HandleHash", "Phone", "DisplayName"];
        foreach (var name in forbidden)
            await Assert.That(names.Contains(name)).IsFalse();

        var methods = typeof(ICredentialStore).GetMethods().Select(m => m.Name).ToHashSet(StringComparer.Ordinal);
        await Assert.That(methods.Contains("TryGetAsync")).IsTrue();
        await Assert.That(methods.Any(m => m.Contains("Email", StringComparison.OrdinalIgnoreCase)
                                          || m.Contains("Handle", StringComparison.OrdinalIgnoreCase)
                                          || m.Contains("User", StringComparison.OrdinalIgnoreCase))).IsFalse();
    }

    [Test]
    public async Task PasswordGrant_UnknownAccount_SameErrorAsBadPassword()
    {
        await using var provider = CreateProvider();
        var tokens = provider.GetRequiredService<ITokenService>();
        await SeedClientAsync(provider);

        var missing = await tokens.IssueAsync(PasswordRequest(CredentialReference.New(), "password"));
        var wrong = await tokens.IssueAsync(PasswordRequest(await SeedAccountAsync(provider, "password"), "nope"));

        await Assert.That(missing.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
        await Assert.That(wrong.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task PasswordGrant_IssuesEs384Jwt()
    {
        await using var provider = CreateProvider();
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        await SeedClientAsync(provider);
        var account = await SeedAccountAsync(provider, "correct horse battery staple");

        var issued = await tokens.IssueAsync(PasswordRequest(account, "correct horse battery staple"));
        await Assert.That(issued.Succeeded).IsTrue();

        var validated = await tokens.ValidateAsync(issued.AccessToken!);
        await Assert.That(validated.IsValid).IsTrue();
        await Assert.That(validated.ClaimsIdentity?.FindFirst("sub")?.Value).IsEqualTo(account.Value.ToString("D"));
        await Assert.That(issued.RefreshToken).IsNotNull();
    }

    [Test]
    public async Task Refresh_Rotates_AndReuseRevokesFamily()
    {
        await using var provider = CreateProvider();
        var tokens = provider.GetRequiredService<ITokenService>();
        await SeedClientAsync(provider);
        var account = await SeedAccountAsync(provider, "pw");

        var first = await tokens.IssueAsync(PasswordRequest(account, "pw"));
        var rotated = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "app",
            ClientSecret = "client-secret",
            RefreshToken = first.RefreshToken,
        });
        await Assert.That(rotated.Succeeded).IsTrue();
        await Assert.That(rotated.RefreshToken)!.IsNotEqualTo(first.RefreshToken);

        var replay = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "app",
            ClientSecret = "client-secret",
            RefreshToken = first.RefreshToken,
        });
        await Assert.That(replay.Succeeded).IsFalse();
        await Assert.That(replay.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);

        var afterReuse = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "app",
            ClientSecret = "client-secret",
            RefreshToken = rotated.RefreshToken,
        });
        await Assert.That(afterReuse.Succeeded).IsFalse();
    }

    [Test]
    public async Task ClientCredentials_OmitsRefresh_AndNarrowsScope()
    {
        await using var provider = CreateProvider();
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        await SeedClientAsync(provider);

        var issued = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "app",
            ClientSecret = "client-secret",
            Scope = "api",
        });
        await Assert.That(issued.Succeeded).IsTrue();
        await Assert.That(issued.RefreshToken).IsNull();
        await Assert.That(issued.Scope).IsEqualTo("api");

        var denied = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "app",
            ClientSecret = "client-secret",
            Scope = "admin",
        });
        await Assert.That(denied.Error).IsEqualTo(OAuthTokenErrors.InvalidScope);
    }

    [Test]
    public async Task DisabledClient_SameErrorAsBadSecret()
    {
        await using var provider = CreateProvider();
        await SeedClientAsync(provider);
        var clients = provider.GetRequiredService<IClientStore>();
        var client = (await clients.FindByClientIdAsync("app"))!;
        client.Disabled = true;
        await clients.UpsertAsync(client);
        var tokens = provider.GetRequiredService<ITokenService>();
        var result = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "app",
            ClientSecret = "client-secret",
        });
        await Assert.That(result.Error).IsEqualTo(OAuthTokenErrors.InvalidClient);
    }

    [Test]
    public async Task EventStore_RecordsIssuedAndDenied()
    {
        var recorded = new List<SecurityEvent>();
        var services = new ServiceCollection();
        services.AddLogging();
        services.Configure<PasswordHasherOptions>(FastArgon);
        OAuthServiceCollectionExtensions.AddNovolisOAuth(services, o =>
        {
            o.Issuer = "https://idp.test";
            o.IsDevelopment = true;
            o.AllowEphemeralSigningKey = true;
        });
        services.Replace(ServiceDescriptor.Singleton<IEventStore>(new RecordingEventStore(recorded)));
        await using var provider = services.BuildServiceProvider();
        await SeedClientAsync(provider);
        var tokens = provider.GetRequiredService<ITokenService>();
        await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "app",
            ClientSecret = "wrong",
        });
        await Assert.That(recorded.Any(e => e.Type == SecurityEventTypes.TokenDenied)).IsTrue();
    }

    [Test]
    public async Task EphemeralKey_ForbiddenOutsideDevelopment()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        OAuthServiceCollectionExtensions.AddNovolisOAuth(services, o =>
        {
            o.IsDevelopment = false;
            o.AllowEphemeralSigningKey = true;
        });
        await using var provider = services.BuildServiceProvider();
        var act = () => provider.GetRequiredService<ITokenService>();
        await Assert.That(act).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task WebEndpoints_TokenAndJwks_RoundTrip()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development" });
        builder.WebHost.UseTestServer();
        builder.Services.Configure<PasswordHasherOptions>(FastArgon);
        OAuthAspNetCoreServiceCollectionExtensions.AddNovolisOAuth(builder.Services, o =>
        {
            o.Issuer = "https://idp.test";
            o.AllowEphemeralSigningKey = true;
        });
        await using var app = builder.Build();
        app.MapNovolisOAuth();
        await app.StartAsync();

        await SeedClientAsync(app.Services);
        var account = await SeedAccountAsync(app.Services, "pw");
        var client = app.GetTestClient();

        using var tokenResponse = await client.PostAsync(
            "/oauth/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["client_id"] = "app",
                ["client_secret"] = "client-secret",
                ["username"] = account.Value.ToString("D"),
                ["password"] = "pw",
            }));
        await Assert.That(tokenResponse.StatusCode).IsEqualTo(HttpStatusCode.OK);
        var payload = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>();
        await Assert.That(payload.GetProperty("access_token").GetString()).IsNotNull();

        using var jwks = await client.GetAsync("/.well-known/jwks.json");
        await Assert.That(jwks.StatusCode).IsEqualTo(HttpStatusCode.OK);
        var keys = await jwks.Content.ReadFromJsonAsync<JsonElement>();
        await Assert.That(keys.GetProperty("keys").GetArrayLength()).IsEqualTo(1);
        await Assert.That(keys.GetProperty("keys")[0].GetProperty("alg").GetString()).IsEqualTo("ES384");
    }

    [Test]
    public async Task RepositoryStores_PasswordGrant_PersistsRefresh()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.Configure<PasswordHasherOptions>(FastArgon);
        OAuthServiceCollectionExtensions.AddNovolisOAuth(services, o =>
        {
            o.Issuer = "https://idp.test";
            o.IsDevelopment = true;
            o.AllowEphemeralSigningKey = true;
        });
        services.AddStorage(b => b.AddInMemoryProvider());
        services.AddNovolisOAuthStorage();
        await using var provider = services.BuildServiceProvider();

        await SeedClientAsync(provider);
        var account = await SeedAccountAsync(provider, "pw");
        var tokens = provider.GetRequiredService<ITokenService>();
        var issued = await tokens.IssueAsync(PasswordRequest(account, "pw"));
        await Assert.That(issued.Succeeded).IsTrue();

        var refreshRepo = provider.GetRequiredService<IRepository<RefreshTokenRecord>>();
        await Assert.That(refreshRepo.All().Any()).IsTrue();
    }

    static TokenIssueRequest PasswordRequest(CredentialReference account, string password) => new()
    {
        GrantType = OAuthGrantTypes.Password,
        ClientId = "app",
        ClientSecret = "client-secret",
        CredentialReference = account,
        Password = password,
    };

    static void FastArgon(PasswordHasherOptions o)
    {
        o.MemorySizeKiB = 32;
        o.Iterations = 1;
        o.DegreeOfParallelism = 1;
    }

    static ServiceProvider CreateProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.Configure<PasswordHasherOptions>(FastArgon);
        OAuthServiceCollectionExtensions.AddNovolisOAuth(services, o =>
        {
            o.Issuer = "https://idp.test";
            o.IsDevelopment = true;
            o.AllowEphemeralSigningKey = true;
        });
        return services.BuildServiceProvider();
    }

    static async Task SeedClientAsync(IServiceProvider services)
    {
        var hasher = services.GetRequiredService<PasswordHasher>();
        var clients = services.GetRequiredService<IClientStore>();
        await clients.UpsertAsync(new OAuthClient
        {
            Id = Guid.CreateVersion7(),
            ClientId = "app",
            SecretHash = hasher.HashPassword("client-secret"),
            Confidential = true,
            AllowedGrantTypes =
            [
                OAuthGrantTypes.Password,
                OAuthGrantTypes.RefreshToken,
                OAuthGrantTypes.ClientCredentials,
            ],
            AllowedScopes = ["openid", "api"],
            AllowedAudiences = ["novolis"],
        });
    }

    static async Task<CredentialReference> SeedAccountAsync(IServiceProvider services, string password)
    {
        var hasher = services.GetRequiredService<PasswordHasher>();
        var accounts = services.GetRequiredService<ICredentialStore>();
        var id = CredentialReference.New();
        await accounts.UpsertAsync(new CredentialRecord
        {
            Id = id.Value,
            PasswordHash = hasher.HashPassword(password),
            CreatedUtc = DateTimeOffset.UtcNow,
        });
        return id;
    }

    sealed class RecordingEventStore(List<SecurityEvent> sink) : IEventStore
    {
        public ValueTask RecordAsync(SecurityEvent evt, CancellationToken ct = default)
        {
            sink.Add(evt);
            return ValueTask.CompletedTask;
        }
    }
}
