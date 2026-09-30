using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Novolis.Security.OAuth;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class OAuthAttackSurfaceTests
{
    [Test]
    public async Task AuthorizationCodeGrant_Unsupported()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var tokens = provider.GetRequiredService<ITokenService>();
        var result = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = "authorization_code",
            ClientId = "app",
            ClientSecret = "client-secret",
            Password = "code",
        });
        await Assert.That(result.Error).IsEqualTo(OAuthTokenErrors.UnsupportedGrantType);
    }

    [Test]
    public async Task ImplicitAndDeviceAndJwtBearerGrants_Unsupported()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var tokens = provider.GetRequiredService<ITokenService>();
        foreach (var grant in new[]
                 {
                     "implicit",
                     "urn:ietf:params:oauth:grant-type:device_code",
                     "urn:ietf:params:oauth:grant-type:jwt-bearer",
                     "urn:ietf:params:oauth:grant-type:token-exchange",
                 })
        {
            var result = await tokens.IssueAsync(new TokenIssueRequest
            {
                GrantType = grant,
                ClientId = "app",
                ClientSecret = "client-secret",
            });
            await Assert.That(result.Error).IsEqualTo(OAuthTokenErrors.UnsupportedGrantType);
        }
    }

    [Test]
    public async Task Refresh_CannotEscalateScope()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var account = await OAuthTestHost.SeedAccountAsync(provider, "pw");
        var tokens = provider.GetRequiredService<ITokenService>();
        var issued = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.Password,
            ClientId = "app",
            ClientSecret = "client-secret",
            CredentialReference = account,
            Password = "pw",
            Scope = "api",
        });
        var escalated = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "app",
            ClientSecret = "client-secret",
            RefreshToken = issued.RefreshToken,
            Scope = "openid api",
        });
        await Assert.That(escalated.Error).IsEqualTo(OAuthTokenErrors.InvalidScope);

        var same = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "app",
            ClientSecret = "client-secret",
            RefreshToken = issued.RefreshToken,
        });
        await Assert.That(same.Succeeded).IsTrue();
        await Assert.That(same.Scope).IsEqualTo("api");
        await Assert.That(same.Scope!.Contains("openid", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task Refresh_Expired_Fails()
    {
        await using var provider = OAuthTestHost.CreateProvider(o => o.RefreshTokenLifetime = TimeSpan.FromSeconds(-1));
        await OAuthTestHost.SeedClientAsync(provider);
        var account = await OAuthTestHost.SeedAccountAsync(provider, "pw");
        var tokens = provider.GetRequiredService<ITokenService>();
        var issued = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.Password,
            ClientId = "app",
            ClientSecret = "client-secret",
            CredentialReference = account,
            Password = "pw",
        });
        var refreshed = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "app",
            ClientSecret = "client-secret",
            RefreshToken = issued.RefreshToken,
        });
        await Assert.That(refreshed.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task RevokeThenRefresh_Fails()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var account = await OAuthTestHost.SeedAccountAsync(provider, "pw");
        var tokens = provider.GetRequiredService<ITokenService>();
        var issued = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.Password,
            ClientId = "app",
            ClientSecret = "client-secret",
            CredentialReference = account,
            Password = "pw",
        });
        var revoked = await tokens.RevokeRefreshTokenAsync(issued.RefreshToken!, "app", "client-secret");
        await Assert.That(revoked).IsTrue();
        var refreshed = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "app",
            ClientSecret = "client-secret",
            RefreshToken = issued.RefreshToken,
        });
        await Assert.That(refreshed.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task RevokeWithoutClient_IsUnauthorized()
    {
        await using var host = await OAuthTestHost.StartAsync();
        using var response = await host.Client.PostAsync(
            "/oauth/revoke",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = "nope" }));
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task ConcurrentRefresh_AtMostOneSucceeds()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var account = await OAuthTestHost.SeedAccountAsync(provider, "pw");
        var tokens = provider.GetRequiredService<ITokenService>();
        var issued = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.Password,
            ClientId = "app",
            ClientSecret = "client-secret",
            CredentialReference = account,
            Password = "pw",
        });

        var first = tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "app",
            ClientSecret = "client-secret",
            RefreshToken = issued.RefreshToken,
        }).AsTask();
        var second = tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "app",
            ClientSecret = "client-secret",
            RefreshToken = issued.RefreshToken,
        }).AsTask();
        await Task.WhenAll(first, second);

        var wins = new[] { first.Result, second.Result }.Count(r => r.Succeeded);
        await Assert.That(wins).IsEqualTo(1);
        var loss = new[] { first.Result, second.Result }.Single(r => !r.Succeeded);
        await Assert.That(loss.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task SqlAndScriptInjection_InClientId_IsInvalidClient()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services);
        foreach (var evil in new[]
                 {
                     "app' OR 1=1--",
                     "<script>alert(1)</script>",
                     "app\0admin",
                     "../../../etc/passwd",
                     "app\r\nSet-Cookie: x=1",
                 })
        {
            using var response = await host.PostTokenAsync(new()
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = evil,
                ["client_secret"] = "client-secret",
            });
            var expected = evil.Contains('\0') ? HttpStatusCode.BadRequest : HttpStatusCode.Unauthorized;
            await Assert.That(response.StatusCode).IsEqualTo(expected);
            var body = await response.Content.ReadAsStringAsync();
            await Assert.That(body.Contains("<script>", StringComparison.Ordinal)).IsFalse();
            await Assert.That(body.Contains("Set-Cookie", StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    public async Task UsernameNullByteAndNewlines_InvalidGrant()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services);
        var account = await OAuthTestHost.SeedAccountAsync(host.Services, "pw");
        foreach (var evil in new[]
                 {
                     account.Value.ToString("D") + "\0admin",
                     account.Value.ToString("D") + "x",
                     "not-a-guid",
                 })
        {
            using var response = await host.PostTokenAsync(new()
            {
                ["grant_type"] = "password",
                ["client_id"] = "app",
                ["client_secret"] = "client-secret",
                ["username"] = evil,
                ["password"] = "pw",
            });
            await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        }
    }

    [Test]
    public async Task PasswordGrant_MissingUsername_InvalidGrant()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services);
        using var response = await host.PostTokenAsync(new()
        {
            ["grant_type"] = "password",
            ["client_id"] = "app",
            ["client_secret"] = "client-secret",
            ["password"] = "pw",
        });
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        await Assert.That(body.GetProperty("error").GetString()).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task ClientCredentials_OmitsRefreshTokenProperty()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services);
        using var response = await host.PostTokenAsync(new()
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "app",
            ["client_secret"] = "client-secret",
        });
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(HasNoStore(response)).IsTrue();
        var payload = await response.Content.ReadFromJsonAsync<JsonElement>();
        await Assert.That(payload.TryGetProperty("refresh_token", out _)).IsFalse();
        await Assert.That(payload.GetProperty("token_type").GetString()).IsEqualTo("Bearer");
    }

    [Test]
    public async Task Discovery_IgnoresHostHeader()
    {
        await using var host = await OAuthTestHost.StartAsync();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/.well-known/openid-configuration");
        request.Headers.Host = "evil.example";
        using var response = await host.Client.SendAsync(request);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        await Assert.That(json.GetProperty("issuer").GetString()).IsEqualTo("https://idp.test");
        await Assert.That(json.GetProperty("token_endpoint").GetString()!.Contains("evil", StringComparison.OrdinalIgnoreCase))
            .IsFalse();
        await Assert.That(json.TryGetProperty("authorization_endpoint", out _)).IsFalse();
        await Assert.That(json.GetProperty("grant_types_supported").EnumerateArray()
            .Any(e => e.GetString() == "authorization_code")).IsFalse();
    }

    [Test]
    public async Task TokenResponse_HasNoStoreAndNoWildcardCors()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "app",
                ["client_secret"] = "client-secret",
            }),
        };
        request.Headers.TryAddWithoutValidation("Origin", "https://evil.example");
        using var response = await host.Client.SendAsync(request);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(response.Headers.Contains("Access-Control-Allow-Origin")).IsFalse();
        await Assert.That(HasNoStore(response)).IsTrue();
    }

    [Test]
    public async Task BearerAuthorization_DoesNotReplaceFormClient()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services);
        var request = new HttpRequestMessage(HttpMethod.Post, "/oauth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "app",
                ["client_secret"] = "client-secret",
            }),
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "stolen");
        using var response = await host.Client.SendAsync(request);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task MalformedBasic_FallsBackToInvalidClientWhenFormMissing()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services);
        using var response = await host.PostTokenAsync(
            new() { ["grant_type"] = "client_credentials" },
            "%%%not-base64%%%");
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        await Assert.That(body.GetProperty("error").GetString()).IsEqualTo(OAuthTokenErrors.InvalidClient);
    }

    [Test]
    public async Task BasicAuth_AllowsColonInClientSecret()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services, secret: "se:cret:with:colons");
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes("app:se:cret:with:colons"));
        using var response = await host.PostTokenAsync(
            new() { ["grant_type"] = "client_credentials" },
            basic);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task PutAndQueryStringToken_Rejected()
    {
        await using var host = await OAuthTestHost.StartAsync();
        using var put = await host.Client.PutAsync("/oauth/token", new StringContent("grant_type=password"));
        await Assert.That(put.StatusCode).IsEqualTo(HttpStatusCode.MethodNotAllowed);

        using var query = await host.Client.PostAsync(
            "/oauth/token?grant_type=client_credentials&client_id=app&client_secret=client-secret",
            new StringContent("{}", Encoding.UTF8, "application/json"));
        await Assert.That(query.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    [Test]
    public async Task Rs256AndEs256Confusion_Rejected()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var account = await OAuthTestHost.SeedAccountAsync(provider, "pw");
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        var issued = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.Password,
            ClientId = "app",
            ClientSecret = "client-secret",
            CredentialReference = account,
            Password = "pw",
        });
        await Assert.That(issued.Succeeded).IsTrue();

        using var rsa = RSA.Create(2048);
        var rsaToken = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://idp.test",
            Audience = "novolis",
            Subject = new ClaimsIdentity([new Claim("sub", account.Value.ToString("D")), new Claim("scope", "admin")]),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256),
        });
        await Assert.That((await tokens.ValidateAsync(rsaToken)).IsValid).IsFalse();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var es256 = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://idp.test",
            Audience = "novolis",
            Subject = new ClaimsIdentity([new Claim("sub", account.Value.ToString("D"))]),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256),
        });
        await Assert.That((await tokens.ValidateAsync(es256)).IsValid).IsFalse();
    }

    [Test]
    public async Task JkuHeaderInjection_DoesNotValidate()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var account = await OAuthTestHost.SeedAccountAsync(provider, "pw");
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        var issued = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.Password,
            ClientId = "app",
            ClientSecret = "client-secret",
            CredentialReference = account,
            Password = "pw",
        });
        var parts = issued.AccessToken!.Split('.');
        var header = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[0]));
        var injected = header.TrimEnd('}') + ",\"jku\":\"https://evil.example/jwks.json\"}";
        var forged = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(injected)) + "." + parts[1] + "." + parts[2];
        await Assert.That((await tokens.ValidateAsync(forged)).IsValid).IsFalse();
    }

    [Test]
    public async Task ClientCredentials_IgnoresUsernamePassword()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var account = await OAuthTestHost.SeedAccountAsync(provider, "pw");
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        var issued = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "app",
            ClientSecret = "client-secret",
            CredentialReference = account,
            Password = "pw",
        });
        await Assert.That(issued.Succeeded).IsTrue();
        var jwt = new JsonWebToken(issued.AccessToken);
        await Assert.That(jwt.Subject).IsNotEqualTo(account.Value.ToString("D"));
        await Assert.That(issued.RefreshToken).IsNull();
    }

    [Test]
    public async Task AccessToken_DoesNotEmbedPasswordOrEmail()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var account = await OAuthTestHost.SeedAccountAsync(provider, "super-secret-password");
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        var issued = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.Password,
            ClientId = "app",
            ClientSecret = "client-secret",
            CredentialReference = account,
            Password = "super-secret-password",
        });
        await Assert.That(issued.AccessToken!.Contains("super-secret-password", StringComparison.Ordinal)).IsFalse();
        await Assert.That(issued.AccessToken.Contains('@')).IsFalse();
        var payloadJson = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(issued.AccessToken.Split('.')[1]));
        await Assert.That(payloadJson.Contains("email", StringComparison.OrdinalIgnoreCase)).IsFalse();
        await Assert.That(payloadJson.Contains("password", StringComparison.OrdinalIgnoreCase)).IsFalse();
    }

    [Test]
    public async Task WrongClientSecret_SameErrorAsUnknownClient()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var tokens = provider.GetRequiredService<ITokenService>();
        var unknown = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "missing",
            ClientSecret = "client-secret",
        });
        var wrong = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "app",
            ClientSecret = "nope",
        });
        await Assert.That(unknown.Error).IsEqualTo(OAuthTokenErrors.InvalidClient);
        await Assert.That(wrong.Error).IsEqualTo(OAuthTokenErrors.InvalidClient);
        await Assert.That(unknown.ErrorDescription).IsEqualTo(wrong.ErrorDescription);
    }

    [Test]
    public async Task ScopeWithNewlinesAndTabs_DoesNotInjectAdmin()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var account = await OAuthTestHost.SeedAccountAsync(provider, "pw");
        var tokens = provider.GetRequiredService<ITokenService>();
        var issued = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.Password,
            ClientId = "app",
            ClientSecret = "client-secret",
            CredentialReference = account,
            Password = "pw",
            Scope = "api\nadmin\topenid",
        });
        await Assert.That(issued.Succeeded).IsFalse();
        await Assert.That(issued.Error).IsEqualTo(OAuthTokenErrors.InvalidScope);
    }

    [Test]
    public async Task MultipartForm_Rejected()
    {
        await using var host = await OAuthTestHost.StartAsync();
        using var content = new MultipartFormDataContent();
        content.Add(new StringContent("client_credentials"), "grant_type");
        content.Add(new StringContent("app"), "client_id");
        content.Add(new StringContent("client-secret"), "client_secret");
        using var response = await host.Client.PostAsync("/oauth/token", content);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    static bool HasNoStore(HttpResponseMessage response)
    {
        if (response.Headers.CacheControl?.NoStore == true)
            return true;
        return response.Headers.TryGetValues("Cache-Control", out var values)
               && values.Any(v => v.Contains("no-store", StringComparison.OrdinalIgnoreCase));
    }
}
