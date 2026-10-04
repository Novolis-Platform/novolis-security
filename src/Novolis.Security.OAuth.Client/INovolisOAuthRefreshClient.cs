namespace Novolis.Security.OAuth.Client;

/// <summary>Resource client that can exchange an authorization code and revoke tokens.</summary>
/// <typeparam name="TApi">Client key.</typeparam>
public interface INovolisOAuthRefreshClient<TApi> : INovolisOAuthClient<TApi>
    where TApi : OAuthClientKey, new()
{
    /// <summary>Exchanges an S256 authorization code and stores the refresh token.</summary>
    /// <param name="code">Authorization code from the browser redirect.</param>
    /// <param name="codeVerifier">PKCE S256 verifier.</param>
    /// <param name="redirectUri">Exact redirect URI used to obtain the code.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the refresh token is stored.</returns>
    Task ExchangeAuthorizationCodeAsync(
        string code,
        string codeVerifier,
        Uri redirectUri,
        CancellationToken cancellationToken = default);

    /// <summary>Revokes <paramref name="token"/> at the issuer revocation endpoint.</summary>
    /// <param name="token">Access or refresh token.</param>
    /// <param name="tokenTypeHint">Optional <c>token_type_hint</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the revocation call finishes.</returns>
    Task RevokeAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default);
}
