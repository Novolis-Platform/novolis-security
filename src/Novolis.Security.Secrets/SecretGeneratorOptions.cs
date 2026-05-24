namespace Novolis.Security.Secrets;

/// <summary>Options for <see cref="ISecretGenerator.GenerateCharsetSecret"/>.</summary>
public class SecretGeneratorOptions
{
    /// <summary>Length of the generated secret.</summary>
    public int Length { get; set; } = 16;

    /// <summary>Include uppercase letters.</summary>
    public bool IncludeUppercase { get; set; } = true;

    /// <summary>Include lowercase letters.</summary>
    public bool IncludeLowercase { get; set; } = true;

    /// <summary>Include digits.</summary>
    public bool IncludeDigits { get; set; } = true;

    /// <summary>Include special characters.</summary>
    public bool IncludeSpecial { get; set; } = false;

    /// <summary>Include homoglyph characters.</summary>
    public bool IncludeHomoglyphs { get; set; } = false;

    /// <summary>Include whitespace characters.</summary>
    public bool IncludeWhitespace { get; set; } = false;
}
