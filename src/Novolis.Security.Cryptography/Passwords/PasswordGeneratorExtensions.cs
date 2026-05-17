namespace Novolis.Security.Cryptography;

public static class PasswordGeneratorExtensions
{
    public static string GeneratePassword(this PasswordGenerator passwordGenerator) => passwordGenerator.GeneratePassword(new PasswordGeneratorOptions());
    
    public static string GeneratePassword(this PasswordGenerator passwordGenerator, int length) => passwordGenerator.GeneratePassword(new PasswordGeneratorOptions { Length = length });
    
    public static string GeneratePassword(this PasswordGenerator passwordGenerator, int length, bool includeUppercase, bool includeLowercase, bool includeDigits, bool includeSpecial, bool includeHomoglyphs, bool includeWhitespace) => passwordGenerator.GeneratePassword(new PasswordGeneratorOptions
    {
        Length = length,
        IncludeUppercase = includeUppercase,
        IncludeLowercase = includeLowercase,
        IncludeDigits = includeDigits,
        IncludeSpecial = includeSpecial,
        IncludeHomoglyphs = includeHomoglyphs,
        IncludeWhitespace = includeWhitespace
    });
    
    public static string GeneratePassword(this PasswordGenerator passwordGenerator, int length, bool includeUppercase, bool includeLowercase, bool includeDigits, bool includeSpecial, bool includeHomoglyphs) => passwordGenerator.GeneratePassword(new PasswordGeneratorOptions
    {
        Length = length,
        IncludeUppercase = includeUppercase,
        IncludeLowercase = includeLowercase,
        IncludeDigits = includeDigits,
        IncludeSpecial = includeSpecial,
        IncludeHomoglyphs = includeHomoglyphs
    });
}