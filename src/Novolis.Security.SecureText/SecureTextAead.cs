using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Novolis.Security.SecureText;

/// <summary>Authenticated encryption used by the secure-text envelope.</summary>
public static class SecureTextAead
{
    /// <summary>Encrypts a payload using AES-256-GCM and the supplied authenticated header.</summary>
    public static SecureTextCiphertext Seal(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        if (key.Length != SecureTextProtocol.SessionKeyBytes)
            throw new ArgumentException("An AES-256 key is required.", nameof(key));
        if (plaintext.IsEmpty)
            throw new ArgumentException("Plaintext is required.", nameof(plaintext));

        var nonce = RandomNumberGenerator.GetBytes(SecureTextProtocol.NonceBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[SecureTextProtocol.AuthenticationTagBytes];
        using var aes = new AesGcm(key, SecureTextProtocol.AuthenticationTagBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        return new SecureTextCiphertext(nonce, ciphertext, tag);
    }

    /// <summary>Decrypts an AES-GCM envelope and throws when its tag or header is invalid.</summary>
    public static byte[] Open(
        ReadOnlySpan<byte> key,
        SecureTextCiphertext ciphertext,
        ReadOnlySpan<byte> associatedData)
    {
        if (key.Length != SecureTextProtocol.SessionKeyBytes)
            throw new ArgumentException("An AES-256 key is required.", nameof(key));
        ArgumentNullException.ThrowIfNull(ciphertext);

        var plaintext = new byte[ciphertext.Ciphertext.Length];
        using var aes = new AesGcm(key, SecureTextProtocol.AuthenticationTagBytes);
        aes.Decrypt(
            ciphertext.Nonce,
            ciphertext.Ciphertext,
            ciphertext.AuthenticationTag,
            plaintext,
            associatedData);
        return plaintext;
    }
}
