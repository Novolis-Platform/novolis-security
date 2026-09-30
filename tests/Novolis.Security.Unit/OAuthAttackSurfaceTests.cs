using System.Net;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Novolis.Security.OAuth;
using Novolis.Security.OAuth.AspNetCore;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class OAuthAttackSurfaceTests
{
    [Test]
    public async Task Authorize_RejectsUnknownClientAndPlainPkce()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedConfidentialClientAsync(host.Services);

        var unknown = await host.Client.GetAsync("/oauth/authorize?response_type=code&client_id=missing&redirect_uri=https://game.example/callback");
        await Assert.That(unknown.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);

        var plain = await host.Client.GetAsync(
            "/oauth/authorize?response_type=code&client_id=space-game-web&redirect_uri=https://game.example/callback&code_challenge=abc&code_challenge_method=plain");
        await Assert.That(plain.Headers.Location?.ToString().Contains("error=invalid_request", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    public async Task Authorize_WithoutSession_RedirectsAccessDenied()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedConfidentialClientAsync(host.Services);
        var response = await host.Client.GetAsync(
            "/oauth/authorize?response_type=code&client_id=space-game-web&redirect_uri=https://game.example/callback&code_challenge=abc&code_challenge_method=S256");
        await Assert.That(response.Headers.Location?.ToString().Contains("error=access_denied", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    public async Task Authorize_WithSession_IssuesCode()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedConfidentialClientAsync(host.Services);
        var (_, sessionId) = await OAuthTestHost.SeedIdentityAsync(host.Services);
        var request = new HttpRequestMessage(
            HttpMethod.Get,
            "/oauth/authorize?response_type=code&client_id=space-game-web&redirect_uri=https://game.example/callback&code_challenge=abcdefghijklmnopabcdefghijklmnop012&code_challenge_method=S256&scope=game");
        request.Headers.Add("Cookie", $"{OAuthEndpointRouteBuilderExtensions.AuthenticationSessionCookie}={sessionId}");
        var response = await host.Client.SendAsync(request);
        await Assert.That(response.Headers.Location?.ToString().Contains("code=", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    public async Task Token_RejectsJsonBody_AndMismatchedBasic()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var json = await host.Client.PostAsync(
            "/oauth/token",
            new StringContent("{}", Encoding.UTF8, "application/json"));
        await Assert.That(json.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);

        var mismatched = Convert.ToBase64String(Encoding.UTF8.GetBytes("other:secret"));
        var response = await host.PostTokenAsync(
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "space-game-web",
                ["client_secret"] = "client-secret",
            },
            mismatched);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Revoke_UnknownToken_ReturnsOk_AfterClientAuth()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedConfidentialClientAsync(host.Services);
        var response = await host.Client.PostAsync(
            "/oauth/revoke",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = "missing.token",
                ["client_id"] = "space-game-web",
                ["client_secret"] = "client-secret",
            }));
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(response.Headers.CacheControl?.NoStore).IsTrue();
    }
}
