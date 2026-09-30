using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Novolis.Security.Authentication;
using Novolis.Security.OAuth;
using Novolis.Security.OAuth.AspNetCore;
using Novolis.Security.PasswordHashing;

namespace Novolis.Security.Tests;

internal sealed class OAuthTestHost : IAsyncDisposable
{
    public WebApplication App { get; }
    public HttpClient Client { get; }
    public IServiceProvider Services => App.Services;

    OAuthTestHost(WebApplication app, HttpClient client)
    {
        App = app;
        Client = client;
    }

    public static async Task<OAuthTestHost> StartAsync(Action<OAuthOptions>? configure = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development" });
        builder.WebHost.UseTestServer();
        builder.Services.Configure<PasswordHasherOptions>(FastArgon);
        builder.Services.AddNovolisAuthentication();
        OAuthAspNetCoreServiceCollectionExtensions.AddNovolisOAuth(builder.Services, o =>
        {
            o.Issuer = new Uri("https://accounts.test");
            o.Audiences.Clear();
            o.Audiences.Add("space-game-api");
            o.AllowEphemeralSigningKey = true;
            configure?.Invoke(o);
        });
        var app = builder.Build();
        app.MapNovolisOAuth();
        await app.StartAsync();
        return new OAuthTestHost(app, app.GetTestClient());
    }

    public static ServiceProvider CreateProvider(Action<OAuthOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.Configure<PasswordHasherOptions>(FastArgon);
        services.AddNovolisAuthentication();
        OAuthServiceCollectionExtensions.AddNovolisOAuth(services, o =>
        {
            o.Issuer = new Uri("https://accounts.test");
            o.Audiences.Clear();
            o.Audiences.Add("space-game-api");
            o.IsDevelopment = true;
            o.AllowEphemeralSigningKey = true;
            configure?.Invoke(o);
        });
        return services.BuildServiceProvider();
    }

    public static void FastArgon(PasswordHasherOptions o)
    {
        o.MemorySizeKiB = 32;
        o.Iterations = 1;
        o.DegreeOfParallelism = 1;
    }

    public static async Task SeedConfidentialClientAsync(
        IServiceProvider services,
        string clientId = "space-game-web",
        string secret = "client-secret",
        string[]? grants = null,
        string[]? scopes = null,
        string[]? redirectUris = null)
    {
        var hasher = services.GetRequiredService<ClientSecretHasher>();
        var clients = services.GetRequiredService<IClientStore>();
        await clients.UpsertAsync(new OAuthClient
        {
            Id = Guid.NewGuid(),
            ClientId = clientId,
            ClientType = OAuthClientType.Confidential,
            SecretHash = hasher.Hash(secret),
            AllowedGrantTypes = [.. grants ?? [OAuthGrantTypes.AuthorizationCode, OAuthGrantTypes.RefreshToken, OAuthGrantTypes.ClientCredentials]],
            AllowedScopes = [.. scopes ?? ["game", "profile"]],
            AllowedAudiences = ["space-game-api"],
            AllowedRedirectUris = [.. redirectUris ?? ["https://game.example/callback"]],
        });
    }

    public static async Task SeedPublicClientAsync(
        IServiceProvider services,
        string clientId = "space-game-launcher")
    {
        var clients = services.GetRequiredService<IClientStore>();
        await clients.UpsertAsync(new OAuthClient
        {
            Id = Guid.NewGuid(),
            ClientId = clientId,
            ClientType = OAuthClientType.Public,
            AllowedGrantTypes = [OAuthGrantTypes.AuthorizationCode, OAuthGrantTypes.RefreshToken],
            AllowedScopes = ["game", "profile"],
            AllowedAudiences = ["space-game-api"],
            AllowedRedirectUris = ["https://launcher.example/callback"],
        });
    }

    public static async Task<(IdentityId IdentityId, string SessionId)> SeedIdentityAsync(
        IServiceProvider services,
        string identifier = "frank",
        string password = "correct horse battery staple")
    {
        var authentication = services.GetRequiredService<IAuthenticationService>();
        var result = await authentication.RegisterAsync(identifier, password);
        return (result.IdentityId!.Value, result.SessionId!);
    }

    public Task<HttpResponseMessage> PostTokenAsync(Dictionary<string, string> form, string? basic = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/oauth/token")
        {
            Content = new FormUrlEncodedContent(form),
        };
        if (basic is not null)
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", basic);
        return Client.SendAsync(request);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await App.DisposeAsync();
    }
}
