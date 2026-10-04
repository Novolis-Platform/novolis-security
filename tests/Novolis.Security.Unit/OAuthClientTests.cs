using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Novolis.Http.Client;
using Novolis.Security.OAuth;
using Novolis.Security.OAuth.Client;
using TUnit.Core;

namespace Novolis.Security.Tests;

public sealed class OAuthClientTests
{
    [Test]
    public async Task ConfidentialClientCredentials_sends_bearer_and_posts_without_authorization()
    {
        var tokenCalls = 0;
        string? tokenForm = null;
        var handler = new StubHandler
        {
            SendAsyncImpl = async (request, _) =>
            {
                if (request.RequestUri!.AbsolutePath == "/oauth/token")
                {
                    Interlocked.Increment(ref tokenCalls);
                    tokenForm = await request.Content!.ReadAsStringAsync();
                    return JsonOk("""{"access_token":"server-token","token_type":"Bearer","expires_in":3600}""");
                }

                return new HttpResponseMessage(HttpStatusCode.OK);
            },
        };

        await using var provider = BuildConfidential(handler);
        var api = provider.GetRequiredService<INovolisOAuthClient<WarehouseApi>>();
        using var response = await api.SendAsync(new HttpRequestMessage(HttpMethod.Get, "items"));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(tokenCalls).IsEqualTo(1);
        await Assert.That(tokenForm).Contains("grant_type=client_credentials");
        await Assert.That(tokenForm).Contains("client_id=warehouse");
        var tokenPost = handler.Sent.First(request => request.RequestUri!.AbsolutePath == "/oauth/token");
        await Assert.That(tokenPost.Headers.Authorization).IsNull();
        var resource = handler.Sent.Last(request => request.RequestUri!.AbsolutePath == "/items");
        await Assert.That(resource.Headers.Authorization!.Scheme).IsEqualTo("Bearer");
        await Assert.That(resource.Headers.Authorization.Parameter).IsEqualTo("server-token");
    }

    [Test]
    public async Task DPoPClientCredentials_sends_proof_that_passes_mint_validation()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var handler = new StubHandler
        {
            SendAsyncImpl = (request, _) =>
            {
                if (request.RequestUri!.AbsolutePath == "/oauth/token")
                {
                    return Task.FromResult(JsonOk("""{"access_token":"dpop-token","expires_in":3600}"""));
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            },
        };

        var services = new ServiceCollection();
        services.AddNovolisOAuthClient<WarehouseApi>(
            new Uri("https://warehouse.example/"),
            ClientCredentialsCredential.DPoP(
                new Uri("https://login.example/"),
                "warehouse",
                key,
                "warehouse.read",
                new Uri("https://login.example/oauth/token")),
            handler);
        await using var provider = services.BuildServiceProvider();
        var api = provider.GetRequiredService<INovolisOAuthClient<WarehouseApi>>();
        using var response = await api.SendAsync(new HttpRequestMessage(HttpMethod.Get, "items"));

        await Assert.That(response.IsSuccessStatusCode).IsTrue();
        var tokenPost = handler.Sent.First(request => request.RequestUri!.AbsolutePath == "/oauth/token");
        await Assert.That(tokenPost.Headers.Authorization).IsNull();
        await Assert.That(tokenPost.Headers.Contains("DPoP")).IsTrue();
        var resource = handler.Sent.Last(request => request.RequestUri!.AbsolutePath == "/items");
        await Assert.That(resource.Headers.Authorization!.Scheme).IsEqualTo("DPoP");
        var proof = resource.Headers.GetValues("DPoP").Single();
        var checkedProof = await DPoPProof.ValidateAsync(
            proof,
            "GET",
            "https://warehouse.example/items",
            TimeProvider.System,
            TimeSpan.FromMinutes(2),
            "dpop-token");
        await Assert.That(checkedProof.Succeeded).IsTrue();
    }

    [Test]
    public async Task Refresh_persists_rotated_token_and_invalid_grant_forgets()
    {
        var store = new MemoryRefreshStore();
        await store.SetAsync(HttpClientKey.For<WarehouseApi>(), "first-refresh");
        var time = new FakeTimeProvider();
        var grantCalls = new List<string>();
        var handler = new StubHandler
        {
            SendAsyncImpl = async (request, _) =>
            {
                if (request.RequestUri!.AbsolutePath != "/oauth/token")
                {
                    return new HttpResponseMessage(HttpStatusCode.OK);
                }

                var form = await request.Content!.ReadAsStringAsync();
                grantCalls.Add(form);
                if (form.Contains("first-refresh", StringComparison.Ordinal))
                {
                    return JsonOk("""{"access_token":"a1","refresh_token":"second-refresh","expires_in":61}""");
                }

                return Json("""{"error":"invalid_grant"}""", HttpStatusCode.BadRequest);
            },
        };

        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(time);
        services.AddSingleton(store);
        services.AddNovolisOAuthClient<WarehouseApi, MemoryRefreshStore>(
            new Uri("https://warehouse.example/"),
            RefreshCredential.Confidential(
                new Uri("https://login.example/"),
                "warehouse",
                "secret",
                "warehouse.read",
                new Uri("https://login.example/oauth/token")),
            handler);
        await using var provider = services.BuildServiceProvider();
        var api = provider.GetRequiredService<INovolisOAuthRefreshClient<WarehouseApi>>();
        using var first = await api.SendAsync(new HttpRequestMessage(HttpMethod.Get, "items"));
        await Assert.That(first.IsSuccessStatusCode).IsTrue();
        await Assert.That(await store.GetAsync(HttpClientKey.For<WarehouseApi>())).IsEqualTo("second-refresh");
        time.Advance(TimeSpan.FromSeconds(2));

        var thrown = await Assert.That(async () =>
            await api.SendAsync(new HttpRequestMessage(HttpMethod.Get, "items")))
            .Throws<InvalidOperationException>();
        await Assert.That(thrown!.Message).Contains("invalid_grant");
        await Assert.That(await store.GetAsync(HttpClientKey.For<WarehouseApi>())).IsNull();
        await Assert.That(grantCalls.Any(form => form.Contains("client_credentials", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task Unauthorized_retries_once_with_a_new_dpop_jti()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var tokens = 0;
        var handler = new StubHandler
        {
            SendAsyncImpl = (request, _) =>
            {
                if (request.RequestUri!.AbsolutePath == "/oauth/token")
                {
                    var token = Interlocked.Increment(ref tokens) == 1 ? "first" : "second";
                    return Task.FromResult(JsonOk($"{{\"access_token\":\"{token}\",\"expires_in\":3600}}"));
                }

                if (request.Headers.Authorization?.Parameter == "first")
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            },
        };

        var services = new ServiceCollection();
        services.AddNovolisOAuthClient<WarehouseApi>(
            new Uri("https://warehouse.example/"),
            ClientCredentialsCredential.DPoP(
                new Uri("https://login.example/"),
                "warehouse",
                key,
                "warehouse.read",
                new Uri("https://login.example/oauth/token")),
            handler);
        await using var provider = services.BuildServiceProvider();
        using var response = await provider.GetRequiredService<INovolisOAuthClient<WarehouseApi>>()
            .SendAsync(new HttpRequestMessage(HttpMethod.Get, "items"));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        var resources = handler.Sent.Where(request => request.RequestUri!.AbsolutePath == "/items").ToArray();
        await Assert.That(resources.Length).IsEqualTo(2);
        var firstJti = ReadJti(resources[0].Headers.GetValues("DPoP").Single());
        var secondJti = ReadJti(resources[1].Headers.GetValues("DPoP").Single());
        await Assert.That(firstJti).IsNotEqualTo(secondJti);
        await Assert.That(tokens).IsEqualTo(2);
    }

    [Test]
    public async Task RefreshRegistration_throws_when_store_is_missing()
    {
        var services = new ServiceCollection();
        await Assert.That(() =>
            services.AddNovolisOAuthClient<WarehouseApi, MemoryRefreshStore>(
                new Uri("https://warehouse.example/"),
                RefreshCredential.Confidential(
                    new Uri("https://login.example/"),
                    "warehouse",
                    "secret",
                    "warehouse.read")))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task TokenClient_has_no_resource_authorization_handler()
    {
        var handler = new StubHandler
        {
            SendAsyncImpl = (request, _) =>
            {
                if (request.RequestUri!.AbsolutePath == "/oauth/token")
                {
                    return Task.FromResult(JsonOk("""{"access_token":"token","expires_in":3600}"""));
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            },
        };

        await using var provider = BuildConfidential(handler);
        using var response = await provider.GetRequiredService<INovolisOAuthClient<WarehouseApi>>()
            .SendAsync(new HttpRequestMessage(HttpMethod.Get, "items"));

        await Assert.That(response.IsSuccessStatusCode).IsTrue();
        foreach (var tokenPost in handler.Sent.Where(request => request.RequestUri!.AbsolutePath == "/oauth/token"))
        {
            await Assert.That(tokenPost.Headers.Authorization).IsNull();
        }
    }

    private static ServiceProvider BuildConfidential(StubHandler handler)
    {
        var services = new ServiceCollection();
        services.AddNovolisOAuthClient<WarehouseApi>(
            new Uri("https://warehouse.example/"),
            ClientCredentialsCredential.Confidential(
                new Uri("https://login.example/"),
                "warehouse",
                "secret",
                "warehouse.read",
                new Uri("https://login.example/oauth/token")),
            handler);
        return services.BuildServiceProvider();
    }

    private static HttpResponseMessage JsonOk(string json) => Json(json, HttpStatusCode.OK);

    private static HttpResponseMessage Json(string json, HttpStatusCode status) =>
        new(status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };

    private static string ReadJti(string proof)
    {
        var jwt = new JsonWebToken(proof);
        return jwt.Id;
    }

    public sealed class WarehouseApi() : OAuthClientKey;

    public sealed class MemoryRefreshStore : IRotatedRefreshTokenStore
    {
        private readonly Dictionary<string, string> _tokens = new(StringComparer.Ordinal);

        public ValueTask<string?> GetAsync(string clientName, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(_tokens.TryGetValue(clientName, out var token) ? token : null);

        public ValueTask SetAsync(string clientName, string refreshToken, CancellationToken cancellationToken = default)
        {
            _tokens[clientName] = refreshToken;
            return ValueTask.CompletedTask;
        }

        public ValueTask ForgetAsync(string clientName, CancellationToken cancellationToken = default)
        {
            _tokens.Remove(clientName);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Sent { get; } = [];

        public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> SendAsyncImpl { get; set; } =
            (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sent.Add(request);
            return SendAsyncImpl(request, cancellationToken);
        }
    }
}
