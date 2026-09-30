namespace Novolis.Security.Authentication;

/// <summary>Identity-directory access. Identifier lookup is intentionally outside the credential store.</summary>
public interface IIdentityStore
{
    /// <summary>Gets a global identity by id.</summary>
    ValueTask<IdentityRecord?> TryGetAsync(
        IdentityId identityId,
        CancellationToken cancellationToken = default);

    /// <summary>Finds an identity by an application-defined login identifier.</summary>
    ValueTask<IdentityRecord?> FindByIdentifierAsync(
        string identifier,
        CancellationToken cancellationToken = default);

    /// <summary>Inserts or replaces an identity-directory record.</summary>
    ValueTask UpsertAsync(
        IdentityRecord record,
        CancellationToken cancellationToken = default);
}
