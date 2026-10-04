using System.Security.Cryptography;

namespace Novolis.Security.OAuth.Client;

/// <summary>Accepts only ECDSA P-256 keys for DPoP proofs.</summary>
internal static class DPoPSigningKeys
{
    /// <summary>Returns <paramref name="key"/> when it is P-256.</summary>
    /// <param name="key">Host-owned signing key.</param>
    /// <returns>The same key.</returns>
    /// <exception cref="ArgumentException">The key is not ECDSA P-256.</exception>
    public static ECDsa RequireP256(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var parameters = key.ExportParameters(includePrivateParameters: false);
        if (parameters.Q.X is null || parameters.Q.Y is null || parameters.Q.X.Length != 32)
        {
            throw new ArgumentException("DPoP signing keys must be ECDSA P-256.", nameof(key));
        }

        return key;
    }
}
