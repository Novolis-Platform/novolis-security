using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authentication.Storage;

/// <summary>Repository adapter for the isolated credential vault.</summary>
public sealed class RepositoryCredentialStore(IRepository<StoredCredential> repository) : ICredentialStore
{
    /// <inheritdoc />
    public ValueTask<CredentialRecord?> TryGetAsync(
        CredentialReference reference,
        CancellationToken cancellationToken = default)
    {
        var match = repository.All().FirstOrDefault(row => row.Reference == reference.Value);
        return ValueTask.FromResult(match is null ? null : ToRecord(match));
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(
        CredentialRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        return repository.UpsertAsync(
            new StoredCredential
            {
                Id = record.StorageId == Guid.Empty ? Guid.NewGuid() : record.StorageId,
                Reference = record.Reference.Value,
                PasswordHash = record.PasswordHash,
                Disabled = record.Disabled,
                CreatedUtc = record.CreatedUtc,
                UpdatedUtc = record.UpdatedUtc,
            },
            cancellationToken);
    }

    static CredentialRecord ToRecord(StoredCredential row) => new()
    {
        StorageId = row.Id,
        Reference = CredentialReference.FromGuid(row.Reference),
        PasswordHash = row.PasswordHash,
        Disabled = row.Disabled,
        CreatedUtc = row.CreatedUtc,
        UpdatedUtc = row.UpdatedUtc,
    };
}
