using Novolis.Storage.Abstractions;

namespace Novolis.Security.OAuth.Storage;

/// <summary>Repository adapter with process-local atomic refresh rotation.</summary>
public sealed class RepositoryRefreshTokenStore(IRepository<StoredRefreshToken> repository) : IRefreshTokenStore
{
    readonly Lock _gate = new();

    /// <inheritdoc />
    public async ValueTask<RefreshTokenRecord?> TryGetAsync(Guid id, CancellationToken ct = default)
    {
        var row = await repository.TryGetAsync(id, ct).ConfigureAwait(false);
        return row is null ? null : OAuthStorageMapper.ToRefresh(row);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(RefreshTokenRecord token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        return repository.UpsertAsync(OAuthStorageMapper.ToStored(token), ct);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<RefreshTokenRecord>> FindByFamilyIdAsync(Guid familyId, CancellationToken ct = default)
    {
        IReadOnlyList<RefreshTokenRecord> matches = repository.All()
            .Where(t => t.FamilyId == familyId)
            .Select(OAuthStorageMapper.ToRefresh)
            .ToArray();
        return ValueTask.FromResult(matches);
    }

    /// <inheritdoc />
    public async ValueTask<RefreshRotationResult> TryRotateAsync(
        Guid currentId,
        RefreshTokenRecord replacement,
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        lock (_gate)
        {
            var current = repository.TryGetAsync(currentId, ct).AsTask().GetAwaiter().GetResult();
            if (current is null)
                return RefreshRotationResult.Failure();
            if (current.RevokedUtc is not null)
                return RefreshRotationResult.Failure(replayed: true);
            if (current.ExpiresUtc <= now)
                return RefreshRotationResult.Failure();

            current.RevokedUtc = now;
            current.ReplacedById = replacement.Id;
            repository.UpsertAsync(current, ct).AsTask().GetAwaiter().GetResult();
            repository.UpsertAsync(OAuthStorageMapper.ToStored(replacement), ct).AsTask().GetAwaiter().GetResult();
            return RefreshRotationResult.Success();
        }
    }

    /// <inheritdoc />
    public async ValueTask RevokeAsync(Guid tokenId, DateTimeOffset revokedUtc, CancellationToken ct = default)
    {
        var token = await repository.TryGetAsync(tokenId, ct).ConfigureAwait(false);
        if (token is null || token.RevokedUtc is not null)
            return;

        token.RevokedUtc = revokedUtc;
        await repository.UpsertAsync(token, ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask RevokeFamilyAsync(Guid familyId, DateTimeOffset revokedUtc, CancellationToken ct = default)
    {
        foreach (var token in repository.All().Where(t => t.FamilyId == familyId && t.RevokedUtc is null))
        {
            token.RevokedUtc = revokedUtc;
            await repository.UpsertAsync(token, ct).ConfigureAwait(false);
        }
    }
}
