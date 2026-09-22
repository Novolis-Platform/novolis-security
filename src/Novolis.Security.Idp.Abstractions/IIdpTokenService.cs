namespace Novolis.Security.Idp;

/// <summary>Issues and revokes tokens for the limited IDP.</summary>
public interface IIdpTokenService
{
    /// <summary>Issues an access token (and refresh token when the grant allows it).</summary>
    ValueTask<TokenIssueResult> IssueAsync(TokenIssueRequest request, CancellationToken ct = default);

    /// <summary>
    /// Revokes a refresh token family after confidential-client authentication.
    /// Returns <see langword="false"/> when client authentication fails.
    /// Returns <see langword="true"/> after the attempt, including unknown tokens (RFC 7009).
    /// </summary>
    ValueTask<bool> RevokeRefreshTokenAsync(
        string refreshToken,
        string? clientId,
        string? clientSecret,
        CancellationToken ct = default);
}
