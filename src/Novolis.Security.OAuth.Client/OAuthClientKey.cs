using Novolis.Http.Client;

namespace Novolis.Security.OAuth.Client;

/// <summary>Base type for a Novolis-issuer resource client. Derived types add no members.</summary>
public class OAuthClientKey : HttpClientKey
{
    /// <summary>Creates a derived key. The base type itself is not a client.</summary>
    /// <exception cref="InvalidOperationException">The runtime type is <see cref="OAuthClientKey"/>.</exception>
    protected OAuthClientKey()
    {
        if (GetType() == typeof(OAuthClientKey))
        {
            throw new InvalidOperationException("OAuthClientKey cannot be used as a client key.");
        }
    }
}
