using System.Security.Cryptography;
using System.Text;
using Novolis.Storage.Abstractions;

namespace Novolis.Security.OAuth.Storage;

/// <summary>Repository adapter with process-local atomic Authorization Code consumption.</summary>
public sealed class RepositoryAuthorizationCodeStore(IRepository<StoredAuthorizationCode> repository)
    : IAuthorizationCodeStore
{
    readonly Lock _gate = new();

    /// <inheritdoc />
    public ValueTask UpsertAsync(AuthorizationCodeRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        return repository.UpsertAsync(OAuthStorageMapper.ToStored(record), cancellationToken);
    }

    /// <inheritdoc />
    public ValueTask<AuthorizationCodeConsumeResult> TryConsumeAsync(
        Guid codeId,
        string secretHash,
        string clientId,
        string redirectUri,
        string codeChallenge,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            var row = repository.TryGetAsync(codeId, cancellationToken).AsTask().GetAwaiter().GetResult();
            if (row is null)
                return ValueTask.FromResult(AuthorizationCodeConsumeResult.Failure());
            if (row.ConsumedUtc is not null)
                return ValueTask.FromResult(AuthorizationCodeConsumeResult.Failure(replayed: true));
            if (row.ExpiresUtc <= now
                || !HashesEqual(row.SecretHash, secretHash)
                || !string.Equals(row.ClientId, clientId, StringComparison.Ordinal)
                || !string.Equals(row.RedirectUri, redirectUri, StringComparison.Ordinal)
                || !string.Equals(row.CodeChallenge, codeChallenge, StringComparison.Ordinal))
                return ValueTask.FromResult(AuthorizationCodeConsumeResult.Failure());

            row.ConsumedUtc = now;
            repository.UpsertAsync(row, cancellationToken).AsTask().GetAwaiter().GetResult();
            return ValueTask.FromResult(AuthorizationCodeConsumeResult.Success(OAuthStorageMapper.ToCode(row)));
        }
    }

    static bool HashesEqual(string left, string right)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(left),
                Convert.FromBase64String(right));
        }
        catch (FormatException)
        {
            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(left),
                Encoding.UTF8.GetBytes(right));
        }
    }
}
