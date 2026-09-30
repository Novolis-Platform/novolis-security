namespace Novolis.Security.OAuth;

/// <summary>Issues and revokes OAuth tokens for an authorization server.</summary>
public interface ITokenService
{
    /// <summary>Issues an access token (and refresh token when the grant allows it).</summary>
    ValueTask<TokenIssueResult> IssueAsync(TokenIssueRequest request, CancellationToken ct = default);

    /// <summary>Issues a short-lived Authorization Code after an authenticated session is established.</summary>
    ValueTask<AuthorizationCodeIssueResult> IssueAuthorizationCodeAsync(
        AuthorizationCodeIssueRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a refresh token after confidential-client authentication.
    /// Unknown token values still return success after valid client authentication (RFC 7009).
    /// </summary>
    ValueTask<bool> RevokeAsync(
        string token,
        string? clientId,
        string? clientSecret,
        string? tokenTypeHint = null,
        CancellationToken ct = default);
}
