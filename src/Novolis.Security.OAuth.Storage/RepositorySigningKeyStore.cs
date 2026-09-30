using Novolis.Storage.Abstractions;

namespace Novolis.Security.OAuth.Storage;

/// <summary>Repository adapter for <see cref="ISigningKeyStore"/>.</summary>
public sealed class RepositorySigningKeyStore(IRepository<StoredSigningKey> repository) : ISigningKeyStore
{
    /// <inheritdoc />
    public ValueTask<IReadOnlyList<SigningKeyRecord>> GetActiveAsync(
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        IReadOnlyList<SigningKeyRecord> matches = repository.All()
            .Where(k => k.Enabled
                && (k.NotBeforeUtc is null || k.NotBeforeUtc <= now)
                && (k.NotAfterUtc is null || k.NotAfterUtc > now))
            .Select(OAuthStorageMapper.ToKey)
            .ToArray();
        return ValueTask.FromResult(matches);
    }

    /// <inheritdoc />
    public ValueTask<SigningKeyRecord?> GetCurrentAsync(
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        var key = repository.All()
            .Where(k => k.Enabled
                && k.Current
                && (k.NotBeforeUtc is null || k.NotBeforeUtc <= now)
                && (k.NotAfterUtc is null || k.NotAfterUtc > now))
            .OrderByDescending(k => k.CreatedUtc)
            .FirstOrDefault();
        return ValueTask.FromResult(key is null ? null : OAuthStorageMapper.ToKey(key));
    }

    /// <inheritdoc />
    public ValueTask<SigningKeyRecord?> GetByKidAsync(string kid, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(kid);
        var match = repository.All().FirstOrDefault(k => string.Equals(k.Kid, kid, StringComparison.Ordinal));
        return ValueTask.FromResult(match is null ? null : OAuthStorageMapper.ToKey(match));
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(SigningKeyRecord key, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        return repository.UpsertAsync(OAuthStorageMapper.ToStored(key), ct);
    }
}
