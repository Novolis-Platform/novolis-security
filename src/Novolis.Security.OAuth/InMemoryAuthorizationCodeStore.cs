using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Novolis.Security.OAuth;

/// <summary>Process-local Authorization Code store with atomic redemption.</summary>
public sealed class InMemoryAuthorizationCodeStore : IAuthorizationCodeStore
{
    readonly ConcurrentDictionary<Guid, AuthorizationCodeRecord> _codes = new();
    readonly Lock _gate = new();

    /// <inheritdoc />
    public ValueTask UpsertAsync(
        AuthorizationCodeRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        _codes[record.Id] = record;
        return ValueTask.CompletedTask;
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
            if (!_codes.TryGetValue(codeId, out var record))
                return ValueTask.FromResult(AuthorizationCodeConsumeResult.Failure());

            if (record.ConsumedUtc is not null)
                return ValueTask.FromResult(AuthorizationCodeConsumeResult.Failure(replayed: true));
            if (record.ExpiresUtc <= now
                || !CryptographicEquals(record.SecretHash, secretHash)
                || !string.Equals(record.ClientId, clientId, StringComparison.Ordinal)
                || !string.Equals(record.RedirectUri, redirectUri, StringComparison.Ordinal)
                || !string.Equals(record.CodeChallenge, codeChallenge, StringComparison.Ordinal))
                return ValueTask.FromResult(AuthorizationCodeConsumeResult.Failure());

            record.ConsumedUtc = now;
            return ValueTask.FromResult(AuthorizationCodeConsumeResult.Success(record));
        }
    }

    static bool CryptographicEquals(string left, string right)
    {
        try
        {
            var leftBytes = Convert.FromBase64String(left);
            var rightBytes = Convert.FromBase64String(right);
            return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        catch (FormatException)
        {
            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(left),
                Encoding.UTF8.GetBytes(right));
        }
    }
}
