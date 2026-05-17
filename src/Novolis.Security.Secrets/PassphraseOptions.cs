namespace Novolis.Security.Secrets;

public class PassphraseOptions
{
    public int WordCount { get; set; } = 4;
    public bool IncludeNouns { get; set; } = true;
    public bool IncludeAdjectives { get; set; } = true;
    public bool IncludeVerbs { get; set; } = true;
    public bool IncludeAdverbs { get; set; } = false;
    public bool IncludeCountries { get; set; } = false;
    public bool IncludeCultures { get; set; } = false;
    public bool IncludeColorNames { get; set; } = false;
}
