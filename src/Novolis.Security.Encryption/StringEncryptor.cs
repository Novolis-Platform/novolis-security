using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Novolis.Security.Cryptography;

namespace Novolis.Security.Encryption;

/// <summary>AES-256-GCM authenticated string encryption. Ciphertext is not decryptable without the tag matching.</summary>
public class StringEncryptor(IOptions<StringEncryptorOptions> options)
{
    const int NonceSize = 12;
    const int TagSize = 16;
    const int KeySize = 32;
    const byte Version = 1;

    /// <summary>Encrypts UTF-8 <paramref name="value"/> with a 32-byte key. Output is versioned Base64 (nonce || tag || ciphertext).</summary>
    public string Encrypt(string value, byte[] key, StringEncryptorOptions? encryptOptions = null)
    {
        ArgumentNullException.ThrowIfNull(value);
        ValidateKey(key);
        _ = encryptOptions ?? options.Value;

        var plaintext = Encoding.UTF8.GetBytes(value);
        var nonce = SecureRandom.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag);

        var packed = new byte[1 + NonceSize + TagSize + ciphertext.Length];
        packed[0] = Version;
        nonce.CopyTo(packed.AsSpan(1));
        tag.CopyTo(packed.AsSpan(1 + NonceSize));
        ciphertext.CopyTo(packed.AsSpan(1 + NonceSize + TagSize));
        return Convert.ToBase64String(packed);
    }

    /// <summary>Decrypts a payload from <see cref="Encrypt"/>. Throws <see cref="CryptographicException"/> when the tag does not match.</summary>
    public string Decrypt(string value, byte[] key, StringEncryptorOptions? decryptOptions = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        ValidateKey(key);
        _ = decryptOptions ?? options.Value;

        var packed = Convert.FromBase64String(value);
        if (packed.Length < 1 + NonceSize + TagSize || packed[0] != Version)
            throw new CryptographicException("Ciphertext is not a Novolis AES-256-GCM payload.");

        var nonce = packed.AsSpan(1, NonceSize);
        var tag = packed.AsSpan(1 + NonceSize, TagSize);
        var ciphertext = packed.AsSpan(1 + NonceSize + TagSize);
        var plaintext = new byte[ciphertext.Length];
        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(nonce, ciphertext, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>Creates a 32-byte key suitable for <see cref="Encrypt"/>.</summary>
    public static byte[] CreateKey() => SecureRandom.GetBytes(KeySize);

    static void ValidateKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != KeySize)
            throw new ArgumentException("AES-256-GCM requires a 32-byte key.", nameof(key));
    }
}
