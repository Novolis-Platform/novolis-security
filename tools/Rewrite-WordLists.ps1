#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$Root = 'd:\novolis\novolis-security\src\Novolis.Security.WordLists'
)
$ErrorActionPreference = 'Stop'
$cs = Join-Path $PSScriptRoot 'Rewrite-WordLists.cs'
& dotnet run --file $cs -- $Root
exit $LASTEXITCODE
