using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Novolis.Security.OAuth;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class OAuthRedTeamTests
{
    static readonly DPoPProofFactory Proofs = new();
    [Test]
    public async Task UnsignedAndHs256Tokens_AreRejected()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        var tokens = provider.GetRequiredService<OAuthTokenService>();
        var unsigned = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            issuer: "https://accounts.test",
            audience: "space-game-api",
            claims: [new Claim("sub", Guid.NewGuid().ToString("D"))],
            expires: DateTime.UtcNow.AddMinutes(5)));
        await Assert.That((await tokens.ValidateAsync(unsigned)).IsValid).IsFalse();

        var hmac = new SigningCredentials(
            new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(64)),
            SecurityAlgorithms.HmacSha256);
        var hs = new JwtSecurityTokenHandler().CreateEncodedJwt(
            "https://accounts.test",
            "space-game-api",
            new ClaimsIdentity([new Claim("sub", Guid.NewGuid().ToString("D"))]),
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(5),
            DateTime.UtcNow,
            hmac);
        await Assert.That((await tokens.ValidateAsync(hs)).IsValid).IsFalse();
    }

    [Test]
    public async Task ConcurrentRefresh_AllowsExactlyOneSuccess()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await OAuthTestHost.SeedConfidentialClientAsync(provider);
        var (identityId, _) = await OAuthTestHost.SeedIdentityAsync(provider);
        var tokens = provider.GetRequiredService<ITokenService>();
        var first = await RedeemAsync(provider, tokens, identityId);
        var results = await Task.WhenAll(
            tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
            {
                GrantType = OAuthGrantTypes.RefreshToken,
                ClientId = "space-game-web",
                ClientSecret = "client-secret",
                RefreshToken = first.RefreshToken,
            })).AsTask(),
            tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
            {
                GrantType = OAuthGrantTypes.RefreshToken,
                ClientId = "space-game-web",
                ClientSecret = "client-secret",
                RefreshToken = first.RefreshToken,
            })).AsTask());
        await Assert.That(results.Count(r => r.Succeeded)).IsEqualTo(1);
    }

    static async Task<TokenIssueResult> RedeemAsync(
        IServiceProvider services,
        ITokenService tokens,
        Novolis.Security.Authentication.IdentityId identityId)
    {
        var oauth = services.GetRequiredService<OAuthTokenService>();
        var bytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Base64UrlEncoder.Encode(bytes);
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier)));
        var code = await oauth.IssueAuthorizationCodeAsync(new AuthorizationCodeIssueRequest
        {
            ClientId = "space-game-web",
            RedirectUri = "https://game.example/callback",
            IdentityId = identityId,
            Scope = "game",
            Audience = "space-game-api",
            CodeChallenge = challenge,
            CodeChallengeMethod = "S256",
        });
        return await tokens.IssueAsync(Proofs.Bind(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.AuthorizationCode,
            ClientId = "space-game-web",
            ClientSecret = "client-secret",
            AuthorizationCode = code.Code,
            RedirectUri = "https://game.example/callback",
            CodeVerifier = verifier,
        }));
    }
}
