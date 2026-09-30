using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authentication.Storage;

/// <summary>Repository adapter for the identity directory.</summary>
public sealed class RepositoryIdentityStore(IRepository<StoredIdentity> repository) : IIdentityStore
{
    /// <inheritdoc />
    public async ValueTask<IdentityRecord?> TryGetAsync(
        IdentityId identityId,
        CancellationToken cancellationToken = default)
    {
        var row = await repository.TryGetAsync(identityId.Value, cancellationToken).ConfigureAwait(false);
        return row is null ? null : ToRecord(row);
    }

    /// <inheritdoc />
    public ValueTask<IdentityRecord?> FindByIdentifierAsync(
        string identifier,
        CancellationToken cancellationToken = default)
    {
        var normalized = Normalize(identifier);
        var match = repository.All().FirstOrDefault(row =>
            string.Equals(Normalize(row.Email), normalized, StringComparison.Ordinal)
            || string.Equals(Normalize(row.Username), normalized, StringComparison.Ordinal));
        return ValueTask.FromResult(match is null ? null : ToRecord(match));
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(
        IdentityRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        return repository.UpsertAsync(
            new StoredIdentity
            {
                Id = record.Id.Value,
                CredentialReference = record.CredentialReference.Value,
                Email = record.Email,
                Username = record.Username,
                DisplayName = record.DisplayName,
                Disabled = record.Disabled,
                CreatedUtc = record.CreatedUtc,
            },
            cancellationToken);
    }

    static IdentityRecord ToRecord(StoredIdentity row) => new()
    {
        Id = IdentityId.FromGuid(row.Id),
        CredentialReference = CredentialReference.FromGuid(row.CredentialReference),
        Email = row.Email,
        Username = row.Username,
        DisplayName = row.DisplayName,
        Disabled = row.Disabled,
        CreatedUtc = row.CreatedUtc,
    };

    static string Normalize(string? identifier) =>
        string.IsNullOrWhiteSpace(identifier) ? "" : identifier.Trim().ToUpperInvariant();
}
