using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Novolis.Security.OAuth;
using Novolis.Security.OAuth.AspNetCore;
using TUnit.Core;

namespace Novolis.Security.Tests;

/// <summary>HTTP authorization-server checks for redirect binding, grant closure, and metadata.</summary>
public class OwaspHttpScenarioTests
{
    [Test]
    public async Task Authorize_RejectsUnregisteredAndPrefixRedirects()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedConfidentialClientAsync(host.Services);

        var evil = await host.Client.GetAsync(
            "/oauth/authorize?response_type=code&client_id=space-game-web&redirect_uri=https://evil.example/callback&code_challenge=abc&code_challenge_method=S256");
        await Assert.That(evil.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(evil.Headers.Location).IsNull();

        var prefix = await host.Client.GetAsync(
            "/oauth/authorize?response_type=code&client_id=space-game-web&redirect_uri=https://game.example/callback.evil&code_challenge=abc&code_challenge_method=S256");
        await Assert.That(prefix.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(prefix.Headers.Location).IsNull();

        var query = await host.Client.GetAsync(
            "/oauth/authorize?response_type=code&client_id=space-game-web&redirect_uri=https://game.example/callback?next=https://evil.example&code_challenge=abc&code_challenge_method=S256");
        await Assert.That(query.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(query.Headers.Location).IsNull();
    }

    [Test]
    public async Task Authorize_RejectsImplicitResponseTypes()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedConfidentialClientAsync(host.Services);
        foreach (var responseType in new[] { "token", "id_token", "code token" })
        {
            var response = await host.Client.GetAsync(
                "/oauth/authorize?response_type=" + Uri.EscapeDataString(responseType)
                + "&client_id=space-game-web&redirect_uri=https://evil.example/callback");
            await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
            await Assert.That(response.Headers.Location).IsNull();
        }
    }

    [Test]
    public async Task Authorize_EchoesState_AndAllowsOmittedState()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedConfidentialClientAsync(host.Services);
        var (_, sessionId) = await OAuthTestHost.SeedIdentityAsync(host.Services);
        var withState = AuthorizedGet(sessionId, "&state=csrf-token");
        var echoed = await host.Client.SendAsync(withState);
        await Assert.That(echoed.Headers.Location?.Query).Contains("state=csrf-token");
        await Assert.That(echoed.Headers.Location?.Query).Contains("code=");

        var omitted = await host.Client.SendAsync(AuthorizedGet(sessionId, ""));
        await Assert.That(omitted.Headers.Location?.Query).Contains("code=");
        await Assert.That(omitted.Headers.Location?.Query.Contains("state=", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task TokenEndpoint_RejectsGet_AndMarksErrorsNoStore()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedConfidentialClientAsync(host.Services);
        var get = await host.Client.GetAsync("/oauth/token");
        await Assert.That(get.StatusCode).IsEqualTo(HttpStatusCode.MethodNotAllowed);

        var password = await host.PostTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "space-game-web",
            ["client_secret"] = "client-secret",
        });
        await Assert.That(password.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(password.Headers.CacheControl?.NoStore).IsTrue();
        var body = await password.Content.ReadFromJsonAsync<JsonElement>();
        await Assert.That(body.GetProperty("error").GetString()).IsEqualTo(OAuthTokenErrors.UnsupportedGrantType);
    }

    [Test]
    public async Task Discovery_IgnoresHostHeader_AndOmitsPasswordGrant()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var request = new HttpRequestMessage(HttpMethod.Get, "/.well-known/oauth-authorization-server");
        request.Headers.TryAddWithoutValidation("Host", "evil.example");
        var response = await host.Client.SendAsync(request);
        var metadata = await response.Content.ReadFromJsonAsync<JsonElement>();
        await Assert.That(metadata.GetProperty("issuer").GetString()).IsEqualTo("https://accounts.test");
        var grants = metadata.GetProperty("grant_types_supported").EnumerateArray().Select(item => item.GetString()).ToArray();
        await Assert.That(grants.Contains("password")).IsFalse();
        await Assert.That(grants.Contains("implicit")).IsFalse();
        await Assert.That(response.Headers.TryGetValues("Access-Control-Allow-Origin", out _)).IsFalse();
    }

    [Test]
    public async Task TokenAttempts_AreLimitedPerClientId()
    {
        await using var provider = OAuthTestHost.CreateProvider(o => o.TokenAttemptsPerWindow = 1);
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        await OAuthTestHost.SeedConfidentialClientAsync(provider, clientId: "second-client", secret: "other-secret");
        var tokens = provider.GetRequiredService<ITokenService>();

        var first = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            Scope = "game",
        });
        await Assert.That(first.Succeeded).IsTrue();

        var limited = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            Scope = "game",
        });
        await Assert.That(limited.Error).IsEqualTo(OAuthTokenErrors.RateLimited);

        var rotated = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "second-client",
            ClientSecret = "other-secret",
            Scope = "game",
        });
        await Assert.That(rotated.Succeeded).IsTrue();
    }

    static HttpRequestMessage AuthorizedGet(string sessionId, string extraQuery)
    {
        var request = new HttpRequestMessage(
            HttpMethod.Get,
            "/oauth/authorize?response_type=code&client_id=space-game-web&redirect_uri=https://game.example/callback"
            + "&code_challenge=abc&code_challenge_method=S256"
            + extraQuery);
        request.Headers.Add("Cookie", $"{OAuthEndpointRouteBuilderExtensions.AuthenticationSessionCookie}={sessionId}");
        return request;
    }
}
