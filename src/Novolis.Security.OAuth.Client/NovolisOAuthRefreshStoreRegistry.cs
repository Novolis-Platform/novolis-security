namespace Novolis.Security.OAuth.Client;

/// <summary>Looks up the refresh-token store bound to a resource client name.</summary>
internal sealed class NovolisOAuthRefreshStoreRegistry(IEnumerable<INovolisOAuthRefreshStoreBinding> bindings)
{
    private readonly Dictionary<string, INovolisOAuthRefreshStoreBinding> _bindings = bindings
        .ToDictionary(binding => binding.ClientName, StringComparer.Ordinal);

    /// <summary>Resolves the store for <paramref name="clientName"/>.</summary>
    public IRotatedRefreshTokenStore Get(string clientName, IServiceProvider services)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientName);
        ArgumentNullException.ThrowIfNull(services);
        if (!_bindings.TryGetValue(clientName, out var binding))
        {
            throw new InvalidOperationException($"No refresh-token store is registered for {clientName}.");
        }

        return binding.Resolve(services);
    }

    /// <summary>Returns whether a store is bound to <paramref name="clientName"/>.</summary>
    public bool Contains(string clientName) =>
        !string.IsNullOrWhiteSpace(clientName) && _bindings.ContainsKey(clientName);
}
