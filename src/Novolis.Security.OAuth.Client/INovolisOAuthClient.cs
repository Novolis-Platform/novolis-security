namespace Novolis.Security.OAuth.Client;

/// <summary>Sends a request through the named Novolis OAuth resource client.</summary>
/// <typeparam name="TApi">Client key.</typeparam>
public interface INovolisOAuthClient<TApi>
    where TApi : OAuthClientKey, new()
{
    /// <summary>Sends <paramref name="request"/> on the registered resource client.</summary>
    /// <param name="request">Resource request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The HTTP response.</returns>
    Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken = default);
}
