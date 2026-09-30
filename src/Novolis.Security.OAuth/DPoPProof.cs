using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Novolis.Security.OAuth;

/// <summary>RFC 9449 DPoP proof checks used at the token endpoint and during access-token validation.</summary>
public static class DPoPProof
{
    /// <summary>Validates a DPoP proof and returns the JWK thumbprint and proof jti.</summary>
    public static async ValueTask<DPoPProofResult> ValidateAsync(
        string proof,
        string httpMethod,
        string httpUri,
        TimeProvider time,
        TimeSpan clockSkew,
        string? accessTokenForAth = null)
    {
        if (string.IsNullOrWhiteSpace(proof) || string.IsNullOrWhiteSpace(httpMethod) || string.IsNullOrWhiteSpace(httpUri))
            return DPoPProofResult.Fail();

        string[] parts;
        try
        {
            parts = proof.Split('.');
            if (parts.Length != 3)
                return DPoPProofResult.Fail();
        }
        catch (Exception)
        {
            return DPoPProofResult.Fail();
        }

        JsonElement header;
        try
        {
            header = JsonDocument.Parse(Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[0]))).RootElement.Clone();
        }
        catch (Exception)
        {
            return DPoPProofResult.Fail();
        }

        if (!header.TryGetProperty("typ", out var typ)
            || !string.Equals(typ.GetString(), "dpop+jwt", StringComparison.OrdinalIgnoreCase))
            return DPoPProofResult.Fail();
        if (!header.TryGetProperty("alg", out var alg)
            || !string.Equals(alg.GetString(), "ES256", StringComparison.Ordinal))
            return DPoPProofResult.Fail();
        if (!header.TryGetProperty("jwk", out var jwkElement) || jwkElement.ValueKind != JsonValueKind.Object)
            return DPoPProofResult.Fail();
        if (jwkElement.TryGetProperty("d", out _))
            return DPoPProofResult.Fail();
        if (!jwkElement.TryGetProperty("kty", out var kty)
            || !string.Equals(kty.GetString(), "EC", StringComparison.Ordinal)
            || !jwkElement.TryGetProperty("crv", out var crv)
            || !string.Equals(crv.GetString(), "P-256", StringComparison.Ordinal)
            || !jwkElement.TryGetProperty("x", out var x)
            || !jwkElement.TryGetProperty("y", out var y))
            return DPoPProofResult.Fail();

        var publicJwk = new JsonWebKey
        {
            Kty = "EC",
            Crv = crv.GetString(),
            X = x.GetString(),
            Y = y.GetString(),
            Alg = SecurityAlgorithms.EcdsaSha256,
        };
        var handler = new JsonWebTokenHandler();
        var validated = await handler.ValidateTokenAsync(
            proof,
            new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                RequireExpirationTime = false,
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = publicJwk,
                ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            }).ConfigureAwait(false);
        if (!validated.IsValid || validated.SecurityToken is not JsonWebToken jwt)
            return DPoPProofResult.Fail();

        if (!jwt.TryGetPayloadValue("htm", out string htm)
            || !string.Equals(htm, httpMethod, StringComparison.OrdinalIgnoreCase))
            return DPoPProofResult.Fail();
        if (!jwt.TryGetPayloadValue("htu", out string htu)
            || !string.Equals(StripQueryAndFragment(htu), StripQueryAndFragment(httpUri), StringComparison.Ordinal))
            return DPoPProofResult.Fail();

        var issuedAt = jwt.IssuedAt;
        var now = time.GetUtcNow().UtcDateTime;
        if (issuedAt == default
            || now + clockSkew < issuedAt
            || now - clockSkew > issuedAt)
            return DPoPProofResult.Fail();

        if (accessTokenForAth is not null)
        {
            var expectedAth = AccessTokenHash(accessTokenForAth);
            if (!jwt.TryGetPayloadValue("ath", out string ath)
                || !string.Equals(ath, expectedAth, StringComparison.Ordinal))
                return DPoPProofResult.Fail();
        }

        var jti = jwt.Id;
        if (string.IsNullOrWhiteSpace(jti))
            return DPoPProofResult.Fail();

        if (string.IsNullOrWhiteSpace(publicJwk.Crv)
            || string.IsNullOrWhiteSpace(publicJwk.X)
            || string.IsNullOrWhiteSpace(publicJwk.Y))
            return DPoPProofResult.Fail();

        var jkt = JsonWebKeyThumbprint.ForEc(publicJwk.Crv, publicJwk.X, publicJwk.Y);
        return DPoPProofResult.Ok(jkt, jti);
    }

    /// <summary>RFC 9449 <c>ath</c> hash of an access token.</summary>
    public static string AccessTokenHash(string accessToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(accessToken);
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
    }

    /// <summary>HTTP URI without query or fragment, as required for <c>htu</c>.</summary>
    public static string StripQueryAndFragment(string uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        var cut = uri.IndexOfAny(['?', '#']);
        return cut < 0 ? uri : uri[..cut];
    }
}
