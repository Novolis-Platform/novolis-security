using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Novolis.Security.SecureText;

/// <summary>AES-GCM output with a unique random nonce and an authentication tag.</summary>
public sealed class SecureTextCiphertext
{
    /// <summary>Creates protected output from validated AES-GCM components.</summary>
    public SecureTextCiphertext(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> authenticationTag)
    {
        if (nonce.Length != SecureTextProtocol.NonceBytes)
            throw new ArgumentException("The AES-GCM nonce length is invalid.", nameof(nonce));
        if (ciphertext.IsEmpty)
            throw new ArgumentException("Ciphertext is required.", nameof(ciphertext));
        if (authenticationTag.Length != SecureTextProtocol.AuthenticationTagBytes)
            throw new ArgumentException("The AES-GCM authentication tag length is invalid.", nameof(authenticationTag));

        Nonce = nonce.ToArray();
        Ciphertext = ciphertext.ToArray();
        AuthenticationTag = authenticationTag.ToArray();
    }

    /// <summary>Random 96-bit AES-GCM nonce.</summary>
    public byte[] Nonce { get; }

    /// <summary>Authenticated encrypted payload.</summary>
    public byte[] Ciphertext { get; }

    /// <summary>128-bit AES-GCM authentication tag.</summary>
    public byte[] AuthenticationTag { get; }
}
