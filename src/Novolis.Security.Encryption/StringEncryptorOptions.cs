using System.Security.Cryptography;

namespace Novolis.Security.Encryption;

public class StringEncryptorOptions
{
    public int KeySize { get; set; } = 256;
    public int BlockSize { get; set; } = 128;
    public PaddingMode Padding { get; set; } = PaddingMode.PKCS7;
}
