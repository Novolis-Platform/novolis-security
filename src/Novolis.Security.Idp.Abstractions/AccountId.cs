namespace Novolis.Security.Idp;

/// <summary>
/// Opaque account primary key shared between the credential store and a separate identifier directory.
/// </summary>
/// <remarks>
/// The credential store keys rows by this id and stores hashes. The identifier directory
/// (email, username, phone) is a different system that maps those values to <see cref="AccountId"/>.
/// Never embed the identifier in this value or in the credential table.
/// </remarks>
/// <param name="Value">Underlying GUID.</param>
public readonly record struct AccountId(Guid Value)
{
    /// <summary>Creates a new time-ordered account id.</summary>
    public static AccountId New() => new(Guid.CreateVersion7());

    /// <summary>Wraps an existing GUID.</summary>
    public static AccountId FromGuid(Guid value) => new(value);

    /// <inheritdoc />
    public override string ToString() => Value.ToString("D");
}
