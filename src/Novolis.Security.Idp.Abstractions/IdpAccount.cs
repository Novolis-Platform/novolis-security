using Novolis.Storage.Abstractions;

namespace Novolis.Security.Idp;

/// <summary>
/// Publishable credential row: opaque <see cref="Id"/>, Argon2id password hash, and non-PII metadata.
/// </summary>
/// <remarks>
/// <para>
/// <b>Store isolation (non-negotiable):</b> putting a username, email, phone, or any other
/// customer identifier in the same table (or backup, replica, or export) as the password hash
/// is a grave violation of minimum secure data-store design. A leaked credential store must
/// not also be a customer directory.
/// </para>
/// <para>
/// Identifier lookup lives in a <i>different system</i>, keyed by <see cref="AccountId"/>.
/// This type has no handle, email, or username field on purpose — do not add one.
/// </para>
/// </remarks>
public sealed class IdpAccount : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Argon2id PHC password hash. Never store the identifier that authenticates this hash here.</summary>
    public string PasswordHash { get; set; } = "";

    /// <summary>When true, token issuance fails closed with <see cref="IdpTokenErrors.InvalidGrant"/>.</summary>
    public bool Disabled { get; set; }

    /// <summary>UTC creation timestamp.</summary>
    public DateTimeOffset CreatedUtc { get; set; }
}
