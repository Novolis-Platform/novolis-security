namespace Novolis.Security.Cryptography;

public class PasswordHasherOptions
{
    public int Iterations { get; set; } = 10000;
    public int SaltSize { get; set; } = 128;
    public int KeySize { get; set; } = 256;
}