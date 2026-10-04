using Microsoft.Extensions.DependencyInjection;

namespace Novolis.Security.OAuth.Client;

/// <summary>Binds <typeparamref name="TStore"/> to one resource client name.</summary>
/// <typeparam name="TStore">Host store type.</typeparam>
internal sealed class NovolisOAuthRefreshStoreBinding<TStore>(string clientName) : INovolisOAuthRefreshStoreBinding
    where TStore : class, IRotatedRefreshTokenStore
{
    /// <inheritdoc />
    public string ClientName { get; } = clientName;

    /// <inheritdoc />
    public IRotatedRefreshTokenStore Resolve(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        var typed = services.GetService<TStore>();
        if (typed is not null)
        {
            return typed;
        }

        var mapped = services.GetService<IRotatedRefreshTokenStore>();
        if (mapped is TStore store)
        {
            return store;
        }

        throw new InvalidOperationException(
            $"{typeof(TStore).Name} is not registered for {ClientName}.");
    }
}
