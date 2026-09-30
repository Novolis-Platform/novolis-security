using Novolis.Security.Cryptography;
using Novolis.Security.WordLists;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class WordListTests
{
    [Test]
    public async Task Instance_IsSingleton_AndEnumerable()
    {
        await Assert.That(ReferenceEquals(Nouns.Instance, Nouns.Instance)).IsTrue();
        await Assert.That(Nouns.Instance.Count).IsGreaterThan(1000);
        await Assert.That(Adjectives.Instance.Count).IsGreaterThan(1000);
        await Assert.That(Verbs.Instance.Count).IsGreaterThan(100);
        await Assert.That(Adverbs.Instance.Count).IsGreaterThan(100);
        await Assert.That(Countries.Instance.Count).IsGreaterThan(50);
        await Assert.That(ColorNames.Instance.Count).IsGreaterThan(50);
        await Assert.That(Cultures.Instance.Count).IsGreaterThan(50);

        var first = Nouns.Instance[0];
        var enumerated = Nouns.Instance.First();
        await Assert.That(enumerated).IsEqualTo(first);

        IEnumerable<string> asEnumerable = Nouns.Instance;
        await Assert.That(asEnumerable.Count()).IsEqualTo(Nouns.Instance.Count);
        await Assert.That(Adjectives.Instance is IEnumerable<string>).IsTrue();
        await Assert.That(Verbs.Instance is IReadOnlyList<string>).IsTrue();
    }

    [Test]
    public async Task Characters_AreCachedReadOnlyLists()
    {
        await Assert.That(ReferenceEquals(Characters.Instance, Characters.Instance)).IsTrue();
        await Assert.That(Characters.Uppercase.Count).IsEqualTo(26);
        await Assert.That(Characters.Digits.Count).IsEqualTo(10);
        await Assert.That(Characters.All.Count).IsEqualTo(65535);
        await Assert.That(ReferenceEquals(Characters.All, Characters.All)).IsTrue();
    }
}
