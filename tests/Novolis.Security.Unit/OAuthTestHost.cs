using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
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
        OAuthAspNetCoreServiceCollectionExtensions.AddNovolisOAuth(builder.Services, o =>
        {
            o.Issuer = "https://idp.test";
            o.Audiences.Clear();
            o.Audiences.Add("novolis");
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
        OAuthServiceCollectionExtensions.AddNovolisOAuth(services, o =>
        {
            o.Issuer = "https://idp.test";
            o.Audiences.Clear();
            o.Audiences.Add("novolis");
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

    public static async Task SeedClientAsync(
        IServiceProvider services,
        string clientId = "app",
        string secret = "client-secret",
        bool confidential = true,
        string[]? grants = null,
        string[]? scopes = null)
    {
        var hasher = services.GetRequiredService<PasswordHasher>();
        var clients = services.GetRequiredService<IClientStore>();
        await clients.UpsertAsync(new OAuthClient
        {
            Id = Guid.CreateVersion7(),
            ClientId = clientId,
            SecretHash = hasher.HashPassword(secret),
            Confidential = confidential,
            AllowedGrantTypes = [.. grants ?? [OAuthGrantTypes.Password, OAuthGrantTypes.RefreshToken, OAuthGrantTypes.ClientCredentials]],
            AllowedScopes = [.. scopes ?? ["openid", "api"]],
            AllowedAudiences = ["novolis"],
        });
    }

    public static async Task<CredentialReference> SeedAccountAsync(IServiceProvider services, string password, bool disabled = false)
    {
        var hasher = services.GetRequiredService<PasswordHasher>();
        var accounts = services.GetRequiredService<ICredentialStore>();
        var id = CredentialReference.New();
        await accounts.UpsertAsync(new CredentialRecord
        {
            Id = id.Value,
            PasswordHash = hasher.HashPassword(password),
            Disabled = disabled,
            CreatedUtc = DateTimeOffset.UtcNow,
        });
        return id;
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
