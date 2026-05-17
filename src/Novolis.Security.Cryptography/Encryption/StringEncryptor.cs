using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Novolis.Security.Cryptography;

public class StringEncryptor(IOptions<StringEncryptorOptions> _options)
{
    public string Encrypt(string value, Guid key, StringEncryptorOptions? options = null)
    {
        options ??= _options.Value;
        var keyBytes = key.ToByteArray();
        using var aes = GetAes(options);
        using var encryptor = aes.CreateEncryptor(keyBytes, aes.IV);
        var ms = new MemoryStream();
        ms.Write(aes.IV, 0, 16); // write the IV to the MemoryStream directly before the CryptoStream is created
        using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        using (var sw = new StreamWriter(cs)) sw.Write(value);
        if (!cs.HasFlushedFinalBlock)
            cs.FlushFinalBlock();
        return Convert.ToBase64String(ms.ToArray());
    }
        
    public string Decrypt(string value, Guid key, StringEncryptorOptions? options = null)
    {
        options ??= _options.Value;
        var keyBytes = key.ToByteArray();
        var bytes = Convert.FromBase64String(value);
        using var aes = GetAes(options);
        var iv = new byte[aes.BlockSize / 8];
        Array.Copy(bytes, 0, iv, 0, iv.Length);
        var encryptedBytes = new byte[bytes.Length - iv.Length];
        Array.Copy(bytes, iv.Length, encryptedBytes, 0, encryptedBytes.Length);
        using var decryptor = aes.CreateDecryptor(keyBytes, iv);
        using var ms = new MemoryStream(encryptedBytes);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var sr = new StreamReader(cs);
        return sr.ReadToEnd();
    }

    private static Aes GetAes(StringEncryptorOptions options)
    {
        var aes = Aes.Create();
        aes.GenerateIV();
        aes.KeySize = options.KeySize;
        aes.BlockSize = options.BlockSize;
        aes.Padding = options.Padding;
        return aes;
    }
}