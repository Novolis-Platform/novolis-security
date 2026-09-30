using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Novolis.Security.Authentication;
using Novolis.Security.OAuth;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class OAuthTokenServiceTests
{
    static readonly DPoPProofFactory Proofs = new();
    [Test]
    public async Task PasswordGrant_IsRejected()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var tokens = provider.GetRequiredService<ITokenService>();
        var result = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = "password",
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
        });
        await Assert.That(result.Error).IsEqualTo(OAuthTokenErrors.UnsupportedGrantType);
    }

    [Test]
    public async Task AuthorizationCode_IssuesEs384Jwt_AndRotatingRefresh()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var (identityId, _) = await OAuthTestHost.SeedIdentityAsync(provider);
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        var (verifier, challenge) = CreatePkce();
        var code = await tokens.IssueAuthorizationCodeAsync(new AuthorizationCodeIssueRequest
        {
            ClientId = "space-game-web",
            RedirectUri = "https://game.example/callback",
            IdentityId = identityId,
            Scope = "game",
            Audience = "space-game-api",
            CodeChallenge = challenge,
            CodeChallengeMethod = "S256",
        });
        await Assert.That(code.Succeeded).IsTrue();

        var issued = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.AuthorizationCode,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            AuthorizationCode = code.Code,
            RedirectUri = "https://game.example/callback",
            CodeVerifier = verifier,
        }));
        await Assert.That(issued.Succeeded).IsTrue();
        await Assert.That(issued.RefreshToken).IsNotNull();
        await Assert.That(issued.IdentityId).IsEqualTo(identityId);

        var validated = await tokens.ValidateAsync(issued.AccessToken!, Proofs.Resource(issued.AccessToken!));
        await Assert.That(validated.IsValid).IsTrue();
        await Assert.That(validated.ClaimsIdentity?.FindFirst("sub")?.Value).IsEqualTo(identityId.ToString());
        await Assert.That(validated.ClaimsIdentity?.FindFirst("client_id")?.Value).IsEqualTo("space-game-web");
    }

    [Test]
    public async Task AuthorizationCode_Replay_Fails()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var (identityId, _) = await OAuthTestHost.SeedIdentityAsync(provider);
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        var (verifier, challenge) = CreatePkce();
        var code = await IssueCodeAsync(tokens, identityId, challenge);
        var request = Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.AuthorizationCode,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            AuthorizationCode = code,
            RedirectUri = "https://game.example/callback",
            CodeVerifier = verifier,
        });
        var first = await tokens.IssueAsync(request);
        await Assert.That(first.Succeeded).IsTrue();
        var replay = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.AuthorizationCode,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            AuthorizationCode = code,
            RedirectUri = "https://game.example/callback",
            CodeVerifier = verifier,
        }));
        await Assert.That(replay.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
        await Assert.That((await tokens.ValidateAsync(first.AccessToken!, Proofs.Resource(first.AccessToken!))).IsValid)
            .IsFalse();
    }

    [Test]
    public async Task AuthorizationCode_WrongVerifierOrRedirect_Fails()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var (identityId, _) = await OAuthTestHost.SeedIdentityAsync(provider);
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        var (verifier, challenge) = CreatePkce();
        var code = await IssueCodeAsync(tokens, identityId, challenge);
        var wrongVerifier = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.AuthorizationCode,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            AuthorizationCode = code,
            RedirectUri = "https://game.example/callback",
            CodeVerifier = "wrong-verifier-value-that-is-long-enough",
        }));
        await Assert.That(wrongVerifier.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task Refresh_Rotates_AndReuseRevokesFamily()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var (identityId, _) = await OAuthTestHost.SeedIdentityAsync(provider);
        var tokens = provider.GetRequiredService<ITokenService>();
        var first = await RedeemAsync(provider, tokens, identityId);

        var rotated = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            RefreshToken = first.RefreshToken,
        }));
        await Assert.That(rotated.Succeeded).IsTrue();
        await Assert.That(rotated.RefreshToken)!.IsNotEqualTo(first.RefreshToken);

        var replay = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            RefreshToken = first.RefreshToken,
        }));
        await Assert.That(replay.Succeeded).IsFalse();

        var afterReuse = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            RefreshToken = rotated.RefreshToken,
        }));
        await Assert.That(afterReuse.Succeeded).IsFalse();
    }

    [Test]
    public async Task Refresh_RejectsScopeAndAudienceEscalation()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var (identityId, _) = await OAuthTestHost.SeedIdentityAsync(provider);
        var tokens = provider.GetRequiredService<ITokenService>();
        var first = await RedeemAsync(provider, tokens, identityId, scope: "game");

        var escalatedScope = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            RefreshToken = first.RefreshToken,
            Scope = "game profile",
        }));
        await Assert.That(escalatedScope.Error).IsEqualTo(OAuthTokenErrors.InvalidScope);

        var escalatedAudience = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            RefreshToken = first.RefreshToken,
            Audience = "farming-api",
        }));
        await Assert.That(escalatedAudience.Error).IsEqualTo(OAuthTokenErrors.InvalidScope);
    }

    [Test]
    public async Task ClientCredentials_OmitsRefresh_AndRejectsPublicClient()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        await OAuthTestHost.SeedPublicClientAsync(provider);
        var tokens = provider.GetRequiredService<OAuthTokenService>();

        var issued = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            Scope = "game",
        }));
        await Assert.That(issued.Succeeded).IsTrue();
        await Assert.That(issued.RefreshToken).IsNull();
        await Assert.That(issued.IdentityId).IsNull();

        var denied = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "space-game-launcher",
        }));
        await Assert.That(denied.Error).IsEqualTo(OAuthTokenErrors.UnauthorizedClient);
    }

    [Test]
    public async Task Discovery_AdvertisesRfc8414_AndRejectsOidcClaims()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var metadata = await host.Client.GetFromJsonAsync<JsonElement>("/.well-known/oauth-authorization-server");
        await Assert.That(metadata.GetProperty("issuer").GetString()).IsEqualTo("https://accounts.test");
        await Assert.That(metadata.GetProperty("authorization_endpoint").GetString())
            .IsEqualTo("https://accounts.test/oauth/authorize");
        await Assert.That(metadata.GetProperty("response_types_supported")[0].GetString()).IsEqualTo("code");
        await Assert.That(metadata.GetProperty("code_challenge_methods_supported")[0].GetString()).IsEqualTo("S256");
        await Assert.That(metadata.TryGetProperty("userinfo_endpoint", out _)).IsFalse();
        await Assert.That(metadata.TryGetProperty("id_token_signing_alg_values_supported", out _)).IsFalse();
        await Assert.That((await host.Client.GetAsync("/.well-known/openid-configuration")).StatusCode)
            .IsEqualTo(HttpStatusCode.NotFound);
    }

    [Test]
    public async Task Jwks_OmitsPrivateMaterial()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var jwks = await host.Client.GetFromJsonAsync<JsonElement>("/.well-known/jwks.json");
        var key = jwks.GetProperty("keys")[0];
        await Assert.That(key.GetProperty("kty").GetString()).IsEqualTo("EC");
        await Assert.That(key.GetProperty("crv").GetString()).IsEqualTo("P-384");
        await Assert.That(key.TryGetProperty("d", out _)).IsFalse();
    }

    [Test]
    public async Task TamperedAndWrongAudienceTokens_AreRejected()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var (identityId, _) = await OAuthTestHost.SeedIdentityAsync(provider);
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        var issued = await RedeemAsync(provider, tokens, identityId);
        var tampered = issued.AccessToken![..^4] + "xxxx";
        var invalid = await tokens.ValidateAsync(tampered);
        await Assert.That(invalid.IsValid).IsFalse();
    }

    [Test]
    public async Task Refresh_FamilyCap_IsAbsolute()
    {
        await using var provider = OAuthTestHost.CreateProvider(o => o.RefreshTokenLifetime = TimeSpan.FromMilliseconds(1));
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var (identityId, _) = await OAuthTestHost.SeedIdentityAsync(provider);
        var tokens = provider.GetRequiredService<ITokenService>();
        var first = await RedeemAsync(provider, tokens, identityId);
        await Task.Delay(30);
        var expired = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            RefreshToken = first.RefreshToken,
        }));
        await Assert.That(expired.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task RevokeGrants_InvalidatesAccessAndRefresh()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var (identityId, sessionId) = await OAuthTestHost.SeedIdentityAsync(provider);
        var authentication = provider.GetRequiredService<IAuthenticationService>();
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        var issued = await RedeemAsync(provider, tokens, identityId);
        await Assert.That(
                (await tokens.ValidateAsync(issued.AccessToken!, Proofs.Resource(issued.AccessToken!))).IsValid)
            .IsTrue();

        await authentication.RevokeGrantsAsync(identityId);
        await Assert.That(await authentication.GetAuthenticatedIdentityAsync(sessionId)).IsNull();
        await Assert.That(
                (await tokens.ValidateAsync(issued.AccessToken!, Proofs.Resource(issued.AccessToken!))).IsValid)
            .IsFalse();
        var refresh = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            RefreshToken = issued.RefreshToken,
        }));
        await Assert.That(refresh.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
    }

    [Test]
    public async Task SigningKeyRing_Rotate_KeepsPreviousKeyForValidation()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        var ring = provider.GetRequiredService<SigningKeyRing>();
        var first = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            Scope = "game",
        }));
        await Assert.That(first.Succeeded).IsTrue();
        var firstKid = new JsonWebToken(first.AccessToken!).Kid;

        using var next = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        await ring.RotateAsync(next.ExportPkcs8PrivateKeyPem());

        var second = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            Scope = "game",
        }));
        await Assert.That(second.Succeeded).IsTrue();
        var secondKid = new JsonWebToken(second.AccessToken!).Kid;
        await Assert.That(secondKid).IsNotEqualTo(firstKid);
        await Assert.That(
                (await tokens.ValidateAsync(first.AccessToken!, Proofs.Resource(first.AccessToken!))).IsValid)
            .IsTrue();
        await Assert.That(
                (await tokens.ValidateAsync(second.AccessToken!, Proofs.Resource(second.AccessToken!))).IsValid)
            .IsTrue();
    }

    [Test]
    public async Task AccessToken_HasAtJwtTyp_AndRejectsDpopProofAsAccessToken()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        var issued = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            Scope = "game",
        }));
        await Assert.That(issued.Succeeded).IsTrue();
        var access = new JsonWebToken(issued.AccessToken!);
        await Assert.That(access.Typ).IsEqualTo("at+jwt");
        var proof = Proofs.Create();
        var dpop = new JsonWebToken(proof);
        await Assert.That(dpop.Typ).IsEqualTo("dpop+jwt");
        await Assert.That(dpop.TryGetPayloadValue("nonce", out string? nonce) && nonce is not null).IsFalse();
        await Assert.That((await tokens.ValidateAsync(proof, Proofs.Resource(issued.AccessToken!))).IsValid).IsFalse();
        var asProof = await tokens.ValidateAsync(
            issued.AccessToken!,
            new TokenProofContext
            {
                DPoPProof = issued.AccessToken,
                HttpMethod = "GET",
                HttpUri = DPoPProofFactory.ResourceUri,
            });
        await Assert.That(asProof.IsValid).IsFalse();
    }

    [Test]
    public async Task ResourceServer_ValidateAsync_RequiresAudience_AndExposesSubScopeClient()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        var issued = await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            Scope = "game",
            Audience = "space-game-api",
        }));
        await Assert.That(issued.Succeeded).IsTrue();
        var validated = await tokens.ValidateAsync(issued.AccessToken!, Proofs.Resource(issued.AccessToken!));
        await Assert.That(validated.IsValid).IsTrue();
        await Assert.That(validated.ClaimsIdentity?.FindFirst("sub")?.Value).IsEqualTo("space-game-web");
        await Assert.That(validated.ClaimsIdentity?.FindFirst("scope")?.Value).IsEqualTo("game");
        await Assert.That(validated.ClaimsIdentity?.FindFirst("client_id")?.Value).IsEqualTo("space-game-web");
        await Assert.That(new JsonWebToken(issued.AccessToken!).Audiences.Contains("space-game-api")).IsTrue();
    }

    static async Task<string> IssueCodeAsync(OAuthTokenService tokens, IdentityId identityId, string challenge)
    {
        var issued = await tokens.IssueAuthorizationCodeAsync(new AuthorizationCodeIssueRequest
        {
            ClientId = "space-game-web",
            RedirectUri = "https://game.example/callback",
            IdentityId = identityId,
            Scope = "game",
            Audience = "space-game-api",
            CodeChallenge = challenge,
            CodeChallengeMethod = "S256",
        });
        return issued.Code!;
    }

    static async Task<TokenIssueResult> RedeemAsync(
        IServiceProvider services,
        ITokenService tokens,
        IdentityId identityId,
        string scope = "game")
    {
        var oauth = services.GetRequiredService<OAuthTokenService>();
        var (verifier, challenge) = CreatePkce();
        var code = await IssueCodeAsync(oauth, identityId, challenge);
        return await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.AuthorizationCode,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            AuthorizationCode = code,
            RedirectUri = "https://game.example/callback",
            CodeVerifier = verifier,
            Scope = scope,
        }));
    }

    static (string Verifier, string Challenge) CreatePkce()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Base64UrlEncoder.Encode(bytes);
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }
}
