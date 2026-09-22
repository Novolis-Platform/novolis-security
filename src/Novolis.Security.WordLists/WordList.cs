using System.Collections;

namespace Novolis.Security.WordLists;

/// <summary>Process-wide immutable word list. Enumerate the static <c>Instance</c> property on each concrete type.</summary>
public abstract class WordList : IReadOnlyList<string>
{
    readonly string[] _words;

    private protected WordList(string[] words)
    {
        ArgumentNullException.ThrowIfNull(words);
        _words = words;
    }

    /// <inheritdoc />
    public int Count => _words.Length;

    /// <inheritdoc />
    public string this[int index] => _words[index];

    /// <inheritdoc />
    public IEnumerator<string> GetEnumerator() => ((IEnumerable<string>)_words).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => _words.GetEnumerator();
}
