namespace Novolis.Security.OAuth;

/// <summary>Dedicated storage contract for one-time Authorization Codes.</summary>
public interface IAuthorizationCodeStore
{
    /// <summary>Persists a newly issued code record.</summary>
    ValueTask UpsertAsync(
        AuthorizationCodeRecord record,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically validates the secret and bindings, consumes the code, and returns the record.
    /// A failed secret or binding must not consume a valid code.
    /// </summary>
    ValueTask<AuthorizationCodeConsumeResult> TryConsumeAsync(
        Guid codeId,
        string secretHash,
        string clientId,
        string redirectUri,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}
