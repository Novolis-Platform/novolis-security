using System.Security.Cryptography;

namespace Novolis.Security.Encryption;

/// <summary>AES options for <see cref="StringEncryptor"/>.</summary>
public class StringEncryptorOptions
{
    /// <summary>AES key size in bits.</summary>
    public int KeySize { get; set; } = 256;

    /// <summary>AES block size in bits.</summary>
    public int BlockSize { get; set; } = 128;

    /// <summary>Padding mode for CBC operations.</summary>
    public PaddingMode Padding { get; set; } = PaddingMode.PKCS7;
}
