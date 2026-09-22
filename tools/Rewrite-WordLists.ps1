param(
    [string] $Root = 'd:\novolis\novolis-security\src\Novolis.Security.WordLists'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$lists = @(
    @{ File = 'Adjectives.cs'; Type = 'Adjectives'; Summary = 'English adjectives for passphrase generation.' },
    @{ File = 'Adverbs.cs'; Type = 'Adverbs'; Summary = 'English adverbs for passphrase generation.' },
    @{ File = 'Nouns.cs'; Type = 'Nouns'; Summary = 'English nouns for passphrase generation. Some have spaces, hyphens, or apostrophes.' },
    @{ File = 'Verbs.cs'; Type = 'Verbs'; Summary = 'English verbs for passphrase generation.' },
    @{ File = 'Countries.cs'; Type = 'Countries'; Summary = 'Country names for passphrase generation.' },
    @{ File = 'ColorNames.cs'; Type = 'ColorNames'; Summary = 'Color names for passphrase generation.' },
    @{ File = 'Cultures.cs'; Type = 'Cultures'; Summary = 'Culture names for passphrase generation.' }
)

foreach ($list in $lists) {
    $path = Join-Path $Root $list.File
    $lines = [System.IO.File]::ReadAllLines($path)
    $words = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        $trim = $line.Trim()
        if ($trim.StartsWith('"') -and ($trim.EndsWith('"') -or $trim.EndsWith('",'))) {
            $words.Add($trim.TrimEnd(','))
        }
    }
    if ($words.Count -lt 10) {
        throw "Parsed too few words from $path ($($words.Count))."
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('namespace Novolis.Security.WordLists;')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("/// <summary>$($list.Summary)</summary>")
    [void]$sb.AppendLine("/// <remarks>Process-wide singleton <see cref=""Instance""/>. The word array is loaded once.</remarks>")
    [void]$sb.AppendLine("public sealed class $($list.Type) : WordList")
    [void]$sb.AppendLine('{')
    [void]$sb.AppendLine('    static readonly string[] Words =')
    [void]$sb.AppendLine('    [')
    foreach ($word in $words) {
        [void]$sb.AppendLine("        $word,")
    }
    [void]$sb.AppendLine('    ];')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("    $($list.Type)() : base(Words) { }")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("    /// <summary>The in-memory word list. Prefer this over allocating a new collection.</summary>")
    [void]$sb.AppendLine("    public static $($list.Type) Instance { get; } = new();")
    [void]$sb.AppendLine('}')
    [System.IO.File]::WriteAllText($path, $sb.ToString())
    Write-Host "Wrote $($list.Type) ($($words.Count) words)"
}
