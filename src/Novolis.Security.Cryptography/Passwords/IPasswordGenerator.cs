namespace Novolis.Security.Cryptography;

public interface IPasswordGenerator
{
    string GeneratePassword();
    
    string GeneratePassword(PasswordGeneratorOptions options);
}