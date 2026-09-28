using Novolis.Security.Idp;
using Novolis.Storage.Abstractions;

namespace Novolis.Security.Idp.Storage;

/// <summary><see cref="IRepository{T}"/> adapter for <see cref="IRefreshTokenStore"/>.</summary>
public sealed class RepositoryRefreshTokenStore(IRepository<IdpRefreshToken> repository) : IRefreshTokenStore
{
    /// <inheritdoc />
    public ValueTask<IdpRefreshToken?> TryGetAsync(Guid id, CancellationToken ct = default) =>
        repository.TryGetAsync(id, ct);

    /// <inheritdoc />
    public ValueTask UpsertAsync(IdpRefreshToken token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        return repository.UpsertAsync(token, ct);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<IdpRefreshToken>> FindByFamilyIdAsync(Guid familyId, CancellationToken ct = default)
    {
        IReadOnlyList<IdpRefreshToken> matches = repository.All().Where(t => t.FamilyId == familyId).ToArray();
        return ValueTask.FromResult(matches);
    }

    /// <inheritdoc />
    public async ValueTask<bool> TryRotateAsync(Guid currentId, IdpRefreshToken replacement, CancellationToken ct = default)
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
