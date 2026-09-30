using System.Security.Cryptography;

namespace Novolis.Security.Authentication;

/// <summary>Stable, global identifier for an authenticated person or principal.</summary>
public readonly record struct IdentityId(Guid Value)
{
    /// <summary>Creates a non-predictable identity identifier.</summary>
    public static IdentityId New()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        return new IdentityId(new Guid(bytes));
    }

    /// <summary>Wraps an existing GUID.</summary>
    public static IdentityId FromGuid(Guid value) => new(value);

    /// <summary>Parses the canonical GUID form.</summary>
    public static bool TryParse(string? value, out IdentityId identityId)
    {
        if (Guid.TryParse(value, out var guid))
        {
            identityId = new IdentityId(guid);
            return true;
        }

        identityId = default;
        return false;
    }

    /// <inheritdoc />
    public override string ToString() => Value.ToString("D");
}
