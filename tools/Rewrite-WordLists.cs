// Rewrite word-list C# files from quoted string arrays.
//
//   dotnet run --file d:\novolis\novolis-security\tools\Rewrite-WordLists.cs

#:property TargetFramework=net10.0
#:property PublishAot=false
#:property PackAsTool=false
#:property ImplicitUsings=enable
#:property Nullable=enable
#:property ManagePackageVersionsCentrally=false

using System.Text;

var root = args.ElementAtOrDefault(0)
    ?? Path.Combine(Directory.GetParent(Path.GetDirectoryName(ThisFile())!)!.FullName, "src", "Novolis.Security.WordLists");

var lists = new (string File, string Type, string Summary)[]
{
    ("Adjectives.cs", "Adjectives", "English adjectives for passphrase generation."),
    ("Adverbs.cs", "Adverbs", "English adverbs for passphrase generation."),
    ("Nouns.cs", "Nouns", "English nouns for passphrase generation. Some have spaces, hyphens, or apostrophes."),
    ("Verbs.cs", "Verbs", "English verbs for passphrase generation."),
    ("Countries.cs", "Countries", "Country names for passphrase generation."),
    ("ColorNames.cs", "ColorNames", "Color names for passphrase generation."),
    ("Cultures.cs", "Cultures", "Culture names for passphrase generation."),
};

foreach (var list in lists)
{
    var path = Path.Combine(root, list.File);
    var words = File.ReadAllLines(path)
        .Select(l => l.Trim())
        .Where(t => t.StartsWith('"') && (t.EndsWith('"') || t.EndsWith("\",")))
        .Select(t => t.TrimEnd(','))
        .ToList();
    if (words.Count < 10)
        throw new InvalidOperationException($"Parsed too few words from {path} ({words.Count}).");

    var sb = new StringBuilder();
    sb.AppendLine("namespace Novolis.Security.WordLists;");
    sb.AppendLine();
    sb.AppendLine($"/// <summary>{list.Summary}</summary>");
    sb.AppendLine("/// <remarks>Process-wide singleton <see cref=\"Instance\"/>. The word array is loaded once.</remarks>");
    sb.AppendLine($"public sealed class {list.Type} : WordList");
    sb.AppendLine("{");
    sb.AppendLine("    static readonly string[] Words =");
    sb.AppendLine("    [");
    foreach (var word in words)
        sb.AppendLine($"        {word},");
    sb.AppendLine("    ];");
    sb.AppendLine();
    sb.AppendLine($"    {list.Type}() : base(Words) {{ }}");
    sb.AppendLine();
    sb.AppendLine("    /// <summary>The in-memory word list. Prefer this over allocating a new collection.</summary>");
    sb.AppendLine($"    public static {list.Type} Instance {{ get; }} = new();");
    sb.AppendLine("}");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine($"Wrote {list.Type} ({words.Count} words)");
}

return 0;

static string ThisFile([System.Runtime.CompilerServices.CallerFilePath] string path = "") => path;
