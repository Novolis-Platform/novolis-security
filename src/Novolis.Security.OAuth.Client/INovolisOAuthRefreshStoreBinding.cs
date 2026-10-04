namespace Novolis.Security.OAuth.Client;

/// <summary>Resolves the host refresh-token store for one resource client.</summary>
internal interface INovolisOAuthRefreshStoreBinding
{
    /// <summary>Factory name of the resource client.</summary>
    string ClientName { get; }

    /// <summary>Resolves the store registered for this client.</summary>
    IRotatedRefreshTokenStore Resolve(IServiceProvider services);
}
