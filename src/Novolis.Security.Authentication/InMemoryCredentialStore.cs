using System.Collections.Concurrent;

namespace Novolis.Security.Authentication;

/// <summary>Process-local credential vault keyed only by <see cref="CredentialReference"/>.</summary>
public sealed class InMemoryCredentialStore : ICredentialStore
{
    readonly ConcurrentDictionary<CredentialReference, CredentialRecord> _credentials = new();

    /// <inheritdoc />
    public ValueTask<CredentialRecord?> TryGetAsync(
        CredentialReference reference,
        CancellationToken cancellationToken = default)
    {
        _credentials.TryGetValue(reference, out var record);
        return ValueTask.FromResult(record);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(
        CredentialRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        _credentials[record.Reference] = record;
        return ValueTask.CompletedTask;
    }
}
