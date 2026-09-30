using System.Security.Cryptography;

namespace Novolis.Security.Authentication;

/// <summary>Opaque locator for credential material inside the credential store.</summary>
public readonly record struct CredentialReference(Guid Value)
{
    /// <summary>Creates a cryptographically opaque, non-time-ordered reference.</summary>
    public static CredentialReference New()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        return new CredentialReference(new Guid(bytes));
    }

    /// <summary>Wraps an existing GUID.</summary>
    public static CredentialReference FromGuid(Guid value) => new(value);

    /// <summary>Parses the canonical GUID form.</summary>
    public static bool TryParse(string? value, out CredentialReference reference)
    {
        if (Guid.TryParse(value, out var guid))
        {
            reference = new CredentialReference(guid);
            return true;
        }

        reference = default;
        return false;
    }

    /// <inheritdoc />
    public override string ToString() => Value.ToString("D");
}
