namespace Novolis.Security.Cryptography.Internals;

internal static class ListExtensions
{
    public static void Shuffle<T>(this IList<T> list)
    {
        var n = list.Count;
        while (n > 1)
        {
            n--;
            var k = Random.Shared.Next(n + 1);
            (list[k], list[n]) = (list[n], list[k]);
        }
    }
    
    public static void Shuffle<T>(this IList<T> list, uint shuffleCount)
    {
        for (var i = 0; i < shuffleCount; i++) list.Shuffle();
    }
    
    public static T GetRandom<T>(this IList<T> list)
    {
        var index = Random.Shared.Next(0, list.Count);
        return list[index];
    }
}