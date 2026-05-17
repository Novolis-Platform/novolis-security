namespace Novolis.Security.Cryptography;

public class PasswordGeneratorOptions
{
    public int Length { get; set; } = 16;
    public bool IncludeUppercase { get; set; } = true;
    public bool IncludeLowercase { get; set; } = true;
    public bool IncludeDigits { get; set; } = true;
    public bool IncludeSpecial { get; set; } = false;
    public bool IncludeHomoglyphs { get; set; } = false;
    public bool IncludeWhitespace { get; set; } = false;
}