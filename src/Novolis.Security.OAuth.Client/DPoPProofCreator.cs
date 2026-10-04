using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Novolis.Security.OAuth.Client;

/// <summary>Creates RFC 9449 ES256 DPoP proofs.</summary>
internal sealed class DPoPProofCreator
{
    private readonly JsonWebTokenHandler _handler = new();

    /// <summary>Creates a proof for <paramref name="httpMethod"/> and <paramref name="httpUri"/>.</summary>
    /// <param name="key">P-256 signing key.</param>
    /// <param name="httpMethod">HTTP method claim.</param>
    /// <param name="httpUri">HTTP URI claim. Query and fragment are stripped.</param>
    /// <param name="accessToken">Access token hashed into <c>ath</c> when present.</param>
    /// <param name="time">Clock used for <c>iat</c>.</param>
    /// <returns>Compact DPoP JWT.</returns>
    public string Create(
        ECDsa key,
        string httpMethod,
        string httpUri,
        string? accessToken,
        TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpUri);
        ArgumentNullException.ThrowIfNull(time);

        var parameters = key.ExportParameters(includePrivateParameters: false);
        if (parameters.Q.X is null || parameters.Q.Y is null || parameters.Q.X.Length != 32)
        {
            throw new InvalidOperationException("DPoP signing keys must be ECDSA P-256.");
        }

        var jwk = new Dictionary<string, string>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(parameters.Q.X),
            ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y),
        };
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = httpMethod,
            ["htu"] = StripQueryAndFragment(httpUri),
            ["iat"] = time.GetUtcNow().ToUnixTimeSeconds(),
        };
        if (accessToken is not null)
        {
            claims["ath"] = Base64UrlEncoder.Encode(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(accessToken)));
        }

        return _handler.CreateToken(
            new SecurityTokenDescriptor
            {
                TokenType = "dpop+jwt",
                AdditionalHeaderClaims = new Dictionary<string, object>
                {
                    ["jwk"] = jwk,
                },
                Claims = claims,
                SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            });
    }

    /// <summary>HTTP URI without query or fragment, as required for <c>htu</c>.</summary>
    public static string StripQueryAndFragment(string uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        var hash = uri.IndexOf('#');
        if (hash >= 0)
        {
            uri = uri[..hash];
        }

        var query = uri.IndexOf('?');
        return query >= 0 ? uri[..query] : uri;
    }
}
