# Release

This repository publishes with the org CalVer scheme (`2026.1.*`) via `merge.yml` to GitHub Packages when packages are packable.

See [release-policy](https://github.com/Novolis-Platform/novolis-governance/blob/main/docs/release-policy.md).

Published docs: [https://novolis-platform.github.io/.github/novolis-security/](https://novolis-platform.github.io/.github/novolis-security/)

## Packages

- `Novolis.Security.Encryption`
- `Novolis.Security.HaveIBeenPwned`
- `Novolis.Security.PasswordHashing`
- `Novolis.Security.Secrets`
- `Novolis.Security.Authentication.*`
- `Novolis.Security.OAuth.*`
- `Novolis.Security.Authorization.*`

## Consumers

Restore from nuget.org + `https://nuget.pkg.github.com/Novolis-Platform/index.json` only.

Local multi-repo iteration: open `d:\novolis\Novolis.Platform.slnx` (ProjectReference mode) — do not add a local feed.
