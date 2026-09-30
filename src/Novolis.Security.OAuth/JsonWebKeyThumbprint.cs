using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Novolis.Security.OAuth;

/// <summary>RFC 7638 JWK SHA-256 thumbprints for EC public keys.</summary>
public static class JsonWebKeyThumbprint
{
    /// <summary>Returns the Base64URL SHA-256 thumbprint of an EC public JWK.</summary>
    public static string ForEc(string crv, string x, string y)
    {
        ArgumentException.ThrowIfNullOrEmpty(crv);
        ArgumentException.ThrowIfNullOrEmpty(x);
        ArgumentException.ThrowIfNullOrEmpty(y);
        var canonical = "{\"crv\":\"" + crv + "\",\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}";
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
