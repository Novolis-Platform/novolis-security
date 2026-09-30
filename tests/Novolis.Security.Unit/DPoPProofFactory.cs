using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Novolis.Security.OAuth;

namespace Novolis.Security.Tests;

internal sealed class DPoPProofFactory : IDisposable
{
    public const string TokenUri = "https://accounts.test/oauth/token";
    public const string ResourceUri = "https://api.test/resource";

    readonly ECDsa _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    readonly JsonWebTokenHandler _handler = new();

    public string Create(
        string httpMethod = "POST",
        string httpUri = TokenUri,
        string? accessToken = null)
    {
        var parameters = _ecdsa.ExportParameters(includePrivateParameters: false);
        var jwk = new Dictionary<string, string>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(parameters.Q.X!),
            ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y!),
        };
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = httpMethod,
            ["htu"] = DPoPProof.StripQueryAndFragment(httpUri),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };
        if (accessToken is not null)
            claims["ath"] = DPoPProof.AccessTokenHash(accessToken);

        return _handler.CreateToken(
            new SecurityTokenDescriptor
            {
                TokenType = "dpop+jwt",
                AdditionalHeaderClaims = new Dictionary<string, object>
                {
                    ["jwk"] = jwk,
                },
                Claims = claims,
                SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(_ecdsa), SecurityAlgorithms.EcdsaSha256),
            });
    }

    public TokenIssueRequest Bind(TokenIssueRequest request, string httpMethod = "POST", string httpUri = TokenUri) =>
        new()
        {
            GrantType = request.GrantType,
            ClientId = request.ClientId,
            ClientSecret = request.ClientSecret,
            AuthorizationCode = request.AuthorizationCode,
            RedirectUri = request.RedirectUri,
            CodeVerifier = request.CodeVerifier,
            RefreshToken = request.RefreshToken,
            Scope = request.Scope,
            Audience = request.Audience,
            RemoteAddress = request.RemoteAddress,
            DPoPProof = Create(httpMethod, httpUri),
            HttpMethod = httpMethod,
            HttpUri = httpUri,
            CertificateThumbprintSha256 = request.CertificateThumbprintSha256,
        };

    public TokenProofContext Resource(string accessToken, string httpMethod = "GET", string httpUri = ResourceUri) =>
        new()
        {
            DPoPProof = Create(httpMethod, httpUri, accessToken),
            HttpMethod = httpMethod,
            HttpUri = httpUri,
        };

    public void Dispose() => _ecdsa.Dispose();
}
