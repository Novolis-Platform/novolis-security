using Novolis.Security.OAuth;
using Novolis.Storage.Abstractions;

namespace Novolis.Security.OAuth.Storage;

/// <summary><see cref="IRepository{T}"/> adapter for <see cref="IRefreshTokenStore"/>.</summary>
public sealed class RepositoryRefreshTokenStore(IRepository<RefreshTokenRecord> repository) : IRefreshTokenStore
{
    /// <inheritdoc />
    public ValueTask<RefreshTokenRecord?> TryGetAsync(Guid id, CancellationToken ct = default) =>
        repository.TryGetAsync(id, ct);

    /// <inheritdoc />
    public ValueTask UpsertAsync(RefreshTokenRecord token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        return repository.UpsertAsync(token, ct);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<RefreshTokenRecord>> FindByFamilyIdAsync(Guid familyId, CancellationToken ct = default)
    {
        IReadOnlyList<RefreshTokenRecord> matches = repository.All().Where(t => t.FamilyId == familyId).ToArray();
        return ValueTask.FromResult(matches);
    }

    /// <inheritdoc />
    public async ValueTask<bool> TryRotateAsync(Guid currentId, RefreshTokenRecord replacement, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        var current = await repository.TryGetAsync(currentId, ct).ConfigureAwait(false);
        if (current is null || current.RevokedUtc is not null)
            return false;

        current.RevokedUtc = DateTimeOffset.UtcNow;
        await repository.UpsertAsync(current, ct).ConfigureAwait(false);
        await repository.UpsertAsync(replacement, ct).ConfigureAwait(false);
        return true;
    }
}
