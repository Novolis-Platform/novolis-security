using System.Collections.Concurrent;

namespace Novolis.Security.Authentication;

/// <summary>Process-local identity directory for development and tests.</summary>
public sealed class InMemoryIdentityStore : IIdentityStore
{
    readonly ConcurrentDictionary<IdentityId, IdentityRecord> _identities = new();
    readonly ConcurrentDictionary<string, IdentityId> _identifiers = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public ValueTask<IdentityRecord?> TryGetAsync(
        IdentityId identityId,
        CancellationToken cancellationToken = default)
    {
        _identities.TryGetValue(identityId, out var record);
        return ValueTask.FromResult(record);
    }

    /// <inheritdoc />
    public ValueTask<IdentityRecord?> FindByIdentifierAsync(
        string identifier,
        CancellationToken cancellationToken = default)
    {
        var normalized = Normalize(identifier);
        if (!_identifiers.TryGetValue(normalized, out var identityId))
            return ValueTask.FromResult<IdentityRecord?>(null);

        _identities.TryGetValue(identityId, out var record);
        return ValueTask.FromResult(record);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(
        IdentityRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        _identities[record.Id] = record;

        if (!string.IsNullOrWhiteSpace(record.Email))
            _identifiers[Normalize(record.Email)] = record.Id;
        if (!string.IsNullOrWhiteSpace(record.Username))
            _identifiers[Normalize(record.Username)] = record.Id;

        return ValueTask.CompletedTask;
    }

    static string Normalize(string identifier) =>
        identifier.Trim().ToUpperInvariant();
}
