using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Novolis.Security.SecureText;

/// <summary>Constants shared by the secure-text v1 cryptographic protocol.</summary>
public static class SecureTextProtocol
{
    /// <summary>Current wire and key-derivation protocol version.</summary>
    public const int Version = 1;

    /// <summary>Maximum serialized public key length accepted by v1.</summary>
    public const int MaximumPublicKeyBytes = 1024;

    /// <summary>Length of a P-256 ECDSA signature in IEEE P1363 form.</summary>
    public const int SignatureBytes = 64;

    /// <summary>Length of AES-GCM nonces used by v1.</summary>
    public const int NonceBytes = 12;

    /// <summary>Length of AES-GCM authentication tags used by v1.</summary>
    public const int AuthenticationTagBytes = 16;

    /// <summary>Length of the AES-256 key used by v1.</summary>
    public const int SessionKeyBytes = 32;
}
