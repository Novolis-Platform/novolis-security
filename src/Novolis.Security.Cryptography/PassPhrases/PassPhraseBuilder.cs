using Novolis.Security.Cryptography.Internals;
using Novolis.Security.Resources;

namespace Novolis.Security.Cryptography;

/// <summary>
/// Builds a passphrase of the specified word count.
/// </summary>
/// <param name="wordCount"></param>
public class PassPhraseBuilder(int wordCount)
{
    private readonly List<string> _words = [];
    private uint _shuffleCount = 0;

    /// <summary>
    /// Includes nouns in the pass phrase being built.
    /// </summary>
    /// <returns>
    /// The current instance of the PassPhraseBuilder for method chaining.
    /// </returns>
    public PassPhraseBuilder IncludeNouns()
    {
        _words.AddRange(Nouns.Get());
        return this;
    }

    /// <summary>
    /// Adds adjectives to the list of words in the PassPhraseBuilder.
    /// </summary>
    /// <returns>A reference to the PassPhraseBuilder instance.</returns>
    public PassPhraseBuilder IncludeAdjectives()
    {
        _words.AddRange(Adjectives.Get());
        return this;
    }

    /// <summary>
    /// Adds a list of verbs to the pass phrase builder.
    /// </summary>
    /// <returns>The current instance of the PassPhraseBuilder.</returns>
    public PassPhraseBuilder IncludeVerbs()
    {
        _words.AddRange(Verbs.Get());
        return this;
    }

    /// <summary>
    /// Adds adverbs to the pass phrase builder.
    /// </summary>
    /// <returns>A reference to the <see cref="PassPhraseBuilder"/> instance.</returns>
    public PassPhraseBuilder IncludeAdverbs()
    {
        _words.AddRange(Adverbs.Get());
        return this;
    }

    /// <summary>
    /// Includes the names of countries in the passphrase.
    /// </summary>
    /// <returns>
    /// An instance of the PassPhraseBuilder class with the country names included.
    /// </returns>
    public PassPhraseBuilder IncludeCountries()
    {
        _words.AddRange(Countries.Get());
        return this;
    }

    /// <summary>
    /// Shuffles the list of words in the PassPhraseBuilder the specified number of times (default is 1) on build.
    /// </summary>
    /// <returns>
    /// The current instance of the PassPhraseBuilder with the shuffled list of words.
    /// </returns>
    public PassPhraseBuilder Shuffle(uint shuffleCount = 1)
    {
        _shuffleCount = shuffleCount;
        return this;
    }

    public string Build()
    {
        var passPhrase = new List<string>();
        _words.Shuffle(_shuffleCount);
        for (var index = 0; index < wordCount; index++) 
            passPhrase.Add(_words.GetRandom());
        return string.Join(" ", passPhrase);
    }
}