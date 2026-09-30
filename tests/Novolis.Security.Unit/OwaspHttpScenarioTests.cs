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
    public async Task Authorize_FormPost_KeepsCodeOutOfTheQueryString()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedConfidentialClientAsync(host.Services);
        var (_, sessionId) = await OAuthTestHost.SeedIdentityAsync(host.Services);
        var response = await host.Client.SendAsync(
            AuthorizedGet(sessionId, "&response_mode=form_post&state=csrf-token"));
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(response.Headers.Location).IsNull();
        await Assert.That(response.Content.Headers.ContentType?.MediaType).IsEqualTo("text/html");
        var html = await response.Content.ReadAsStringAsync();
        await Assert.That(html).Contains("action=\"https://game.example/callback\"");
        await Assert.That(html).Contains("name=\"code\"");
        await Assert.That(html).Contains("name=\"state\" value=\"csrf-token\"");
        await Assert.That(html).Contains("document.forms[0].submit()");
    }

    [Test]
    public async Task Authorize_FormPost_HtmlEncodesState()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedConfidentialClientAsync(host.Services);
        var (_, sessionId) = await OAuthTestHost.SeedIdentityAsync(host.Services);
        var response = await host.Client.SendAsync(
            AuthorizedGet(sessionId, "&response_mode=form_post&state=" + Uri.EscapeDataString("x\"><script>alert(1)</script>")));
        var html = await response.Content.ReadAsStringAsync();
        await Assert.That(html).Contains("&lt;script&gt;alert(1)&lt;/script&gt;");
        await Assert.That(html.Contains("value=\"x\"><script>", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task TokenError_IsGenericJson_WithoutStackOrSecrets()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedConfidentialClientAsync(host.Services);
        var password = await host.PostTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "space-game-web",
            ["client_secret"] = "client-secret",
        });
        var raw = await password.Content.ReadAsStringAsync();
        await Assert.That(raw.Contains("Exception", StringComparison.Ordinal)).IsFalse();
        await Assert.That(raw.Contains(" at ", StringComparison.Ordinal)).IsFalse();
        await Assert.That(raw.Contains("BEGIN", StringComparison.Ordinal)).IsFalse();
        await Assert.That(raw.Contains("client-secret", StringComparison.Ordinal)).IsFalse();
        var body = JsonSerializer.Deserialize<JsonElement>(raw);
        await Assert.That(body.GetProperty("error").GetString()).IsEqualTo(OAuthTokenErrors.UnsupportedGrantType);
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
        var modes = metadata.GetProperty("response_modes_supported").EnumerateArray()
            .Select(item => item.GetString())
            .ToArray();
        await Assert.That(modes.Contains("query")).IsTrue();
        await Assert.That(modes.Contains("form_post")).IsTrue();
        await Assert.That(response.Headers.TryGetValues("Access-Control-Allow-Origin", out _)).IsFalse();
    }

    [Test]
    public async Task TokenAttempts_AreLimitedPerClientId_AndPerIp()
    {
        await using var provider = OAuthTestHost.CreateProvider(o => o.TokenAttemptsPerWindow = 1);
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        await OAuthTestHost.SeedConfidentialClientAsync(provider, clientId: "second-client", secret: "other-secret");
        await OAuthTestHost.SeedConfidentialClientAsync(provider, clientId: "third-client", secret: "third-secret");
        var tokens = provider.GetRequiredService<ITokenService>();
        using var proofs = new DPoPProofFactory();

        var first = await tokens.IssueAsync(proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            Scope = "game",
            RemoteAddress = "203.0.113.10",
        }));
        await Assert.That(first.Succeeded).IsTrue();

        var limited = await tokens.IssueAsync(proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            Scope = "game",
            RemoteAddress = "203.0.113.10",
        }));
        await Assert.That(limited.Error).IsEqualTo(OAuthTokenErrors.RateLimited);

        var rotated = await tokens.IssueAsync(proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "second-client",
            ClientSecret = "other-secret",
            Scope = "game",
            RemoteAddress = "203.0.113.10",
        }));
        await Assert.That(rotated.Error).IsEqualTo(OAuthTokenErrors.RateLimited);

        var otherIp = await tokens.IssueAsync(proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "third-client",
            ClientSecret = "third-secret",
            Scope = "game",
            RemoteAddress = "203.0.113.11",
        }));
        await Assert.That(otherIp.Succeeded).IsTrue();
    }

    [Test]
    public async Task Production_RejectsInMemoryStores()
    {
        await using var provider = OAuthTestHost.CreateProvider(o =>
        {
            o.IsDevelopment = false;
            o.AllowEphemeralSigningKey = false;
            o.AllowInMemoryStores = false;
        });
        await Assert.That(() => provider.GetRequiredService<OAuthTokenService>()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task DPoP_Mismatch_IsRejected()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        using var proofs = new DPoPProofFactory();
        using var other = new DPoPProofFactory();
        var issued = await tokens.IssueAsync(proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            Scope = "game",
        }));
        await Assert.That(issued.Succeeded).IsTrue();
        var mismatched = await tokens.ValidateAsync(issued.AccessToken!, other.Resource(issued.AccessToken!));
        await Assert.That(mismatched.IsValid).IsFalse();
        var missing = await tokens.ValidateAsync(issued.AccessToken!);
        await Assert.That(missing.IsValid).IsFalse();
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
