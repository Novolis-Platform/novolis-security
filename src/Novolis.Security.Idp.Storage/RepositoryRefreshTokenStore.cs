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
}
