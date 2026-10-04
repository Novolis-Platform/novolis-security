using System.Security.Cryptography;

namespace Novolis.Security.OAuth.Client;

/// <summary>Binds one DPoP signing key to a resource client name.</summary>
internal sealed class NovolisOAuthDPoPKeyBinding(string clientName, ECDsa key) : INovolisOAuthDPoPKeyBinding
{
    /// <inheritdoc />
    public void Apply(NovolisOAuthDPoPKeyRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);
        registry.Set(clientName, key);
    }
}
