using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Novolis.Security.OAuth;
using Novolis.Security.PasswordHashing;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class OAuthRedTeamTests
{
    [Test]
    public async Task EmailAsUsername_IsInvalidGrant_NotLookedUp()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services);
        using var response = await host.PostTokenAsync(new()
        {
            ["grant_type"] = "password",
            ["client_id"] = "app",
            ["client_secret"] = "client-secret",
            ["username"] = "ada@example.com",
            ["password"] = "pw",
        });
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        await Assert.That(body.GetProperty("error").GetString()).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task EmptyGuidUsername_IsInvalidGrant()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services);
        using var response = await host.PostTokenAsync(new()
        {
            ["grant_type"] = "password",
            ["client_id"] = "app",
            ["client_secret"] = "client-secret",
            ["username"] = Guid.Empty.ToString("D"),
            ["password"] = "pw",
        });
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    [Test]
    public async Task JsonBody_Rejected()
    {
        await using var host = await OAuthTestHost.StartAsync();
        using var response = await host.Client.PostAsJsonAsync("/oauth/token", new { grant_type = "password" });
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    [Test]
    public async Task GetToken_NotAllowed()
    {
        await using var host = await OAuthTestHost.StartAsync();
        using var response = await host.Client.GetAsync("/oauth/token");
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.MethodNotAllowed);
    }

    [Test]
    public async Task MissingClientSecret_InvalidClient()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services);
        using var response = await host.PostTokenAsync(new()
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "app",
        });
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        await Assert.That(body.GetProperty("error").GetString()).IsEqualTo(OAuthTokenErrors.InvalidClient);
    }

    [Test]
    public async Task PublicClient_Unauthorized()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider, confidential: false);
        var tokens = provider.GetRequiredService<ITokenService>();
        var result = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "app",
            ClientSecret = "client-secret",
        });
        await Assert.That(result.Error).IsEqualTo(OAuthTokenErrors.UnauthorizedClient);
    }

    [Test]
    public async Task DisabledAccount_InvalidGrant()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var account = await OAuthTestHost.SeedAccountAsync(provider, "pw", disabled: true);
        var tokens = provider.GetRequiredService<ITokenService>();
        var result = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.Password,
            ClientId = "app",
            ClientSecret = "client-secret",
            CredentialReference = account,
            Password = "pw",
        });
        await Assert.That(result.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task EmptyPassword_InvalidGrant()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var account = await OAuthTestHost.SeedAccountAsync(provider, "pw");
        var tokens = provider.GetRequiredService<ITokenService>();
        var result = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.Password,
            ClientId = "app",
            ClientSecret = "client-secret",
            CredentialReference = account,
            Password = "",
        });
        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task OversizedPassword_DoesNotHash()
    {
        var hasher = new PasswordHasher(Microsoft.Extensions.Options.Options.Create(new PasswordHasherOptions
        {
            MemorySizeKiB = 32,
            Iterations = 1,
            MaxPasswordLength = 8,
        }));
        await Assert.That(() => hasher.HashPassword("123456789")).Throws<ArgumentOutOfRangeException>();
        var hash = hasher.HashPassword("short");
        await Assert.That(hasher.CompareHashedPassword(hash, "123456789")).IsFalse();
    }

    [Test]
    public async Task PhcBomb_DoesNotVerify()
    {
        var hasher = new PasswordHasher(Microsoft.Extensions.Options.Options.Create(new PasswordHasherOptions
        {
            MemorySizeKiB = 32,
            Iterations = 1,
            MaxVerifyMemoryKiB = 64,
        }));
        await Assert.That(hasher.CompareHashedPassword("$argon2id$v=19$m=999999,t=99,p=8$YWFhYWFhYWE$YmJiYmJiYmJiYmJiYmJiYg", "pw"))
            .IsFalse();
    }

    [Test]
    public async Task GrantTypeCase_IsOrdinal()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var tokens = provider.GetRequiredService<ITokenService>();
        var result = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = "Password",
            ClientId = "app",
            ClientSecret = "client-secret",
        });
        await Assert.That(result.Error).IsEqualTo(OAuthTokenErrors.UnsupportedGrantType);
    }

    [Test]
    public async Task RefreshFromOtherClient_Fails()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        await OAuthTestHost.SeedClientAsync(provider, clientId: "other", secret: "other-secret");
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
        var stolen = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "other",
            ClientSecret = "other-secret",
            RefreshToken = issued.RefreshToken,
        });
        await Assert.That(stolen.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task AccessTokenUsedAsRefresh_Fails()
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
        var result = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "app",
            ClientSecret = "client-secret",
            RefreshToken = issued.AccessToken,
        });
        await Assert.That(result.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task RefreshIdWithoutSecret_Fails()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedClientAsync(provider);
        var tokens = provider.GetRequiredService<ITokenService>();
        var result = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "app",
            ClientSecret = "client-secret",
            RefreshToken = Guid.CreateVersion7().ToString("N"),
        });
        await Assert.That(result.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task TruncatedRefreshSecret_Fails()
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
        var truncated = issued.RefreshToken![..^2];
        var result = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "app",
            ClientSecret = "client-secret",
            RefreshToken = truncated,
        });
        await Assert.That(result.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task ExpiredAccessToken_DoesNotValidate()
    {
        await using var provider = OAuthTestHost.CreateProvider(o =>
        {
            o.AccessTokenLifetime = TimeSpan.FromHours(-1);
            o.ClockSkew = TimeSpan.Zero;
        });
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
        var validated = await tokens.ValidateAsync(issued.AccessToken!);
        await Assert.That(validated.IsValid).IsFalse();
    }

    [Test]
    public async Task AlgNone_IsRejected()
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
        var headerJson = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[0]));
        var noneHeader = headerJson.Replace("ES384", "none", StringComparison.Ordinal);
        var forged = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(noneHeader)) + "." + parts[1] + ".";
        var validated = await tokens.ValidateAsync(forged);
        await Assert.That(validated.IsValid).IsFalse();
    }

    [Test]
    public async Task Hs256Confusion_UsingJwksAsHmacKey_IsRejected()
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
        var jwk = tokens.GetJsonWebKeySet().Keys[0];
        var hmacKey = Encoding.UTF8.GetBytes(jwk.X + jwk.Y);
        var handler = new JsonWebTokenHandler();
        var confused = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://idp.test",
            Audience = "novolis",
            Subject = new ClaimsIdentity([new Claim("sub", account.Value.ToString("D")), new Claim("scope", "admin")]),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(hmacKey), SecurityAlgorithms.HmacSha256),
        });
        var validated = await tokens.ValidateAsync(confused);
        await Assert.That(validated.IsValid).IsFalse();
    }

    [Test]
    public async Task TamperedPayload_IsRejected()
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
            Scope = "api",
        });
        var parts = issued.AccessToken!.Split('.');
        var payload = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[1]));
        var admin = payload.Replace("\"api\"", "\"admin\"", StringComparison.Ordinal);
        var tampered = parts[0] + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(admin)) + "." + parts[2];
        var validated = await tokens.ValidateAsync(tampered);
        await Assert.That(validated.IsValid).IsFalse();
    }

    [Test]
    public async Task Jwks_HasNoPrivateCoordinates()
    {
        await using var host = await OAuthTestHost.StartAsync();
        using var response = await host.Client.GetAsync("/.well-known/jwks.json");
        var json = await response.Content.ReadAsStringAsync();
        await Assert.That(json.Contains("\"d\"", StringComparison.Ordinal)).IsFalse();
        await Assert.That(json.Contains("\"p\"", StringComparison.OrdinalIgnoreCase) || json.Contains("\"x\"")).IsTrue();
        var doc = JsonDocument.Parse(json);
        var key = doc.RootElement.GetProperty("keys")[0];
        await Assert.That(key.TryGetProperty("d", out _)).IsFalse();
        await Assert.That(key.GetProperty("alg").GetString()).IsEqualTo("ES384");
        await Assert.That(key.GetProperty("crv").GetString()).IsEqualTo("P-384");
    }

    [Test]
    public async Task SubClaim_IsCredentialReference_NotEmail()
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
        var jwt = new JsonWebToken(issued.AccessToken);
        await Assert.That(jwt.Subject).IsEqualTo(account.Value.ToString("D"));
        await Assert.That(jwt.Claims.Any(c => c.Value.Contains('@'))).IsFalse();
    }

    [Test]
    public async Task BasicAndFormClientIdMismatch_InvalidClient()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services);
        await OAuthTestHost.SeedClientAsync(host.Services, clientId: "other", secret: "other-secret");
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes("other:other-secret"));
        using var response = await host.PostTokenAsync(
            new()
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "app",
                ["client_secret"] = "client-secret",
            },
            basic);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        await Assert.That(body.GetProperty("error").GetString()).IsEqualTo(OAuthTokenErrors.InvalidClient);
    }

    [Test]
    public async Task BasicAuth_SucceedsWhenFormOmitsClient()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services);
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes("app:client-secret"));
        using var response = await host.PostTokenAsync(
            new() { ["grant_type"] = "client_credentials" },
            basic);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task RevokeUnknown_Returns200()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await OAuthTestHost.SeedClientAsync(host.Services);
        using var response = await host.Client.PostAsync(
            "/oauth/revoke",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = "nope",
                ["client_id"] = "app",
                ["client_secret"] = "client-secret",
            }));
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task WrongAudience_DoesNotValidate()
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
        var parameters = tokens.CreateValidationParameters();
        parameters.ValidAudience = "someone-else";
        parameters.ValidAudiences = ["someone-else"];
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(issued.AccessToken, parameters);
        await Assert.That(result.IsValid).IsFalse();
    }

    [Test]
    public async Task WrongIssuer_DoesNotValidate()
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
        var parameters = tokens.CreateValidationParameters();
        parameters.ValidIssuer = "https://evil.example";
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(issued.AccessToken, parameters);
        await Assert.That(result.IsValid).IsFalse();
    }

    [Test]
    public async Task ScopeNotGranted_CannotAppearInToken()
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
            Scope = "api admin",
        });
        await Assert.That(issued.Succeeded).IsFalse();
        await Assert.That(issued.Error).IsEqualTo(OAuthTokenErrors.InvalidScope);
    }

    [Test]
    public async Task RefreshAfterDisable_Fails()
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
        var stored = await provider.GetRequiredService<ICredentialStore>().TryGetAsync(account);
        stored!.Disabled = true;
        await provider.GetRequiredService<ICredentialStore>().UpsertAsync(stored);
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
    public async Task RateLimiter_EventuallyRejects()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var saw429 = false;
        for (var i = 0; i < 40; i++)
        {
            using var response = await host.PostTokenAsync(new()
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "missing",
                ["client_secret"] = "x",
            });
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                saw429 = true;
                break;
            }
        }

        await Assert.That(saw429).IsTrue();
    }
}
