namespace Novolis.Security.Idp;

/// <summary>
/// Credential table access by <see cref="AccountId"/> only.
/// </summary>
/// <remarks>
/// <para>
/// Rows are password hashes and non-PII metadata. There is no find-by-email, find-by-username,
/// or handle-hash API — those lookups must happen in a completely different system.
/// </para>
/// <para>
/// Co-locating username/email with the password hash is a grave violation of minimum secure
/// data-store design: one breach then yields both who the customer is and the material to
/// attack their credential. Do not "just add a column" to make login convenient.
/// </para>
/// </remarks>
public interface IAccountStore
{
    /// <summary>Gets an account by opaque <see cref="AccountId"/>. No identifier lookup.</summary>
    ValueTask<IdpAccount?> TryGetAsync(AccountId id, CancellationToken ct = default);

    /// <summary>Inserts or replaces a credential row. The entity must not carry email or username.</summary>
    ValueTask UpsertAsync(IdpAccount account, CancellationToken ct = default);
}
