namespace Novolis.Security.Authentication;

/// <summary>Credential-vault access keyed only by an opaque credential reference.</summary>
public interface ICredentialStore
{
    /// <summary>Gets credential material by opaque reference.</summary>
    ValueTask<CredentialRecord?> TryGetAsync(
        CredentialReference reference,
        CancellationToken cancellationToken = default);

    /// <summary>Inserts or replaces credential material.</summary>
    ValueTask UpsertAsync(
        CredentialRecord record,
        CancellationToken cancellationToken = default);
}
