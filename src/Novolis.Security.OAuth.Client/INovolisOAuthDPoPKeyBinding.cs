namespace Novolis.Security.OAuth.Client;

/// <summary>Applies a host-owned DPoP key to the registry for one client name.</summary>
internal interface INovolisOAuthDPoPKeyBinding
{
    /// <summary>Stores the key on <paramref name="registry"/>.</summary>
    void Apply(NovolisOAuthDPoPKeyRegistry registry);
}
