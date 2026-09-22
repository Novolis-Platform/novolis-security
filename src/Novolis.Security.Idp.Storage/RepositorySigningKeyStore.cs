using Novolis.Security.Idp;
using Novolis.Storage.Abstractions;

namespace Novolis.Security.Idp.Storage;

/// <summary><see cref="IRepository{T}"/> adapter for <see cref="ISigningKeyStore"/>.</summary>
public sealed class RepositorySigningKeyStore(IRepository<IdpSigningKey> repository) : ISigningKeyStore
{
    /// <inheritdoc />
    public ValueTask<IReadOnlyList<IdpSigningKey>> GetActiveAsync(CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        IReadOnlyList<IdpSigningKey> matches = repository.All()
            .Where(k => k.Active && (k.NotAfterUtc is null || k.NotAfterUtc > now))
            .ToArray();
        return ValueTask.FromResult(matches);
    }

    /// <inheritdoc />
    public ValueTask<IdpSigningKey?> GetByKidAsync(string kid, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(kid);
        var match = repository.All().FirstOrDefault(k => string.Equals(k.Kid, kid, StringComparison.Ordinal));
        return ValueTask.FromResult(match);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(IdpSigningKey key, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        return repository.UpsertAsync(key, ct);
    }
}
