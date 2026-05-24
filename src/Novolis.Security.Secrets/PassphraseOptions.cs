namespace Novolis.Security.Secrets;

/// <summary>Options for <see cref="ISecretGenerator.GenerateWordPassphrase"/>.</summary>
public class PassphraseOptions
{
    /// <summary>Number of words in the passphrase.</summary>
    public int WordCount { get; set; } = 4;

    /// <summary>Include nouns from <see cref="WordLists.Nouns"/>.</summary>
    public bool IncludeNouns { get; set; } = true;

    /// <summary>Include adjectives.</summary>
    public bool IncludeAdjectives { get; set; } = true;

    /// <summary>Include verbs.</summary>
    public bool IncludeVerbs { get; set; } = true;

    /// <summary>Include adverbs.</summary>
    public bool IncludeAdverbs { get; set; } = false;

    /// <summary>Include country names.</summary>
    public bool IncludeCountries { get; set; } = false;

    /// <summary>Include culture names.</summary>
    public bool IncludeCultures { get; set; } = false;

    /// <summary>Include color names.</summary>
    public bool IncludeColorNames { get; set; } = false;
}
