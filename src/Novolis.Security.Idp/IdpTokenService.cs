using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Novolis.Security.PasswordHashing;

namespace Novolis.Security.Idp;

/// <summary>Issues ES384 access tokens and rotating refresh tokens for confidential clients.</summary>
public sealed class IdpTokenService : IIdpTokenService
{
    readonly IdpOptions _options;
    readonly IAccountStore _accounts;
    readonly IClientStore _clients;
    readonly IRefreshTokenStore _refresh;
    readonly PasswordHasher _hasher;
    readonly SigningKeyRing _keys;
    readonly TimeProvider _time;
    readonly JsonWebTokenHandler _handler = new();
    readonly SemaphoreSlim _rotation = new(1, 1);
    readonly string _dummyHash;
    static readonly HashSet<string> SupportedGrants =
    [
        IdpGrantTypes.Password,
        IdpGrantTypes.ClientCredentials,
        IdpGrantTypes.RefreshToken,
    ];

    /// <summary>Creates the token service.</summary>
    public IdpTokenService(
        IOptions<IdpOptions> options,
        IAccountStore accounts,
        IClientStore clients,
        IRefreshTokenStore refresh,
        PasswordHasher hasher,
        SigningKeyRing keys,
        TimeProvider time)
    {
        _options = options.Value;
        _accounts = accounts;
        _clients = clients;
        _refresh = refresh;
        _hasher = hasher;
        _keys = keys;
        _time = time;
        _dummyHash = hasher.HashPassword("novolis-idp-timing-dummy");
        ValidateDevelopmentGuards();
    }

    /// <inheritdoc />
    public async ValueTask<TokenIssueResult> IssueAsync(TokenIssueRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.GrantType))
            return TokenIssueResult.Fail(IdpTokenErrors.InvalidRequest, "grant_type is required.");

        var client = await AuthenticateClientAsync(request, ct).ConfigureAwait(false);
        if (client is null)
            return TokenIssueResult.Fail(IdpTokenErrors.InvalidClient);

        if (!client.Confidential)
            return TokenIssueResult.Fail(IdpTokenErrors.UnauthorizedClient, "Public clients are not accepted.");

        if (!SupportedGrants.Contains(request.GrantType))
            return TokenIssueResult.Fail(IdpTokenErrors.UnsupportedGrantType);

        if (!client.AllowedGrantTypes.Contains(request.GrantType, StringComparer.Ordinal))
            return TokenIssueResult.Fail(IdpTokenErrors.UnauthorizedClient);

        return request.GrantType switch
        {
            IdpGrantTypes.Password => await IssuePasswordAsync(request, client, ct).ConfigureAwait(false),
            IdpGrantTypes.ClientCredentials => IssueClientCredentials(request, client),
            IdpGrantTypes.RefreshToken => await IssueRefreshAsync(request, client, ct).ConfigureAwait(false),
            _ => TokenIssueResult.Fail(IdpTokenErrors.UnsupportedGrantType),
        };
    }

    /// <inheritdoc />
    public async ValueTask<bool> RevokeRefreshTokenAsync(
        string refreshToken,
        string? clientId,
        string? clientSecret,
        CancellationToken ct = default)
    {
        var client = await AuthenticateClientAsync(
            new TokenIssueRequest
            {
                GrantType = IdpGrantTypes.RefreshToken,
                ClientId = clientId,
                ClientSecret = clientSecret,
            },
            ct).ConfigureAwait(false);
        if (client is null)
            return false;

        await _rotation.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!RefreshTokenFormat.TryParse(refreshToken, out var id, out var secret))
                return true;

            var row = await _refresh.TryGetAsync(id, ct).ConfigureAwait(false);
            if (row is null || row.ClientId != client.Id || !RefreshTokenFormat.SecretEquals(row.SecretHash, secret))
                return true;

            await RevokeFamilyAsync(row.FamilyId, ct).ConfigureAwait(false);
            return true;
        }
        finally
        {
            _rotation.Release();
        }
    }

    /// <summary>Parameters for validating access tokens issued by this service.</summary>
    public TokenValidationParameters CreateValidationParameters() => new()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidateLifetime = true,
        RequireSignedTokens = true,
        RequireExpirationTime = true,
        RequireAudience = true,
        TryAllIssuerSigningKeys = true,
        ValidIssuer = _options.Issuer,
        ValidAudiences = _options.Audiences,
        IssuerSigningKeys = _keys.GetValidationKeys(),
        ClockSkew = _options.ClockSkew,
        ValidAlgorithms = [SecurityAlgorithms.EcdsaSha384],
    };

    /// <summary>Public JWKS for <c>/.well-known/jwks.json</c>.</summary>
    public JsonWebKeySet GetJsonWebKeySet() => _keys.GetJsonWebKeySet();

    /// <summary>Validates an access token issued by this service.</summary>
    public async ValueTask<TokenValidationResult> ValidateAsync(string token, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        return await _handler.ValidateTokenAsync(token, CreateValidationParameters()).ConfigureAwait(false);
    }

    async ValueTask<IdpClient?> AuthenticateClientAsync(TokenIssueRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.ClientId) || string.IsNullOrWhiteSpace(request.ClientSecret))
            return null;

        var client = await _clients.FindByClientIdAsync(request.ClientId, ct).ConfigureAwait(false);
        if (client is null)
        {
            _hasher.CompareHashedPassword(_dummyHash, request.ClientSecret);
            return null;
        }

        if (!_hasher.CompareHashedPassword(client.SecretHash, request.ClientSecret))
            return null;

        return client;
    }

    async ValueTask<TokenIssueResult> IssuePasswordAsync(TokenIssueRequest request, IdpClient client, CancellationToken ct)
    {
        var password = request.Password ?? "";
        if (request.AccountId is not { } accountId)
        {
            _hasher.CompareHashedPassword(_dummyHash, password);
            return TokenIssueResult.Fail(IdpTokenErrors.InvalidGrant);
        }

        var account = await _accounts.TryGetAsync(accountId, ct).ConfigureAwait(false);
        var hash = account?.PasswordHash ?? _dummyHash;
        var passwordOk = _hasher.CompareHashedPassword(hash, password);
        if (account is null || account.Disabled || !passwordOk)
            return TokenIssueResult.Fail(IdpTokenErrors.InvalidGrant);

        if (!TryGrantScopes(request.Scope, client, out var scope, out var error))
            return error!;

        var access = CreateAccessToken(account.Id.ToString("D"), client, scope);
        var refresh = await CreateRefreshTokenAsync(account.Id, client.Id, Guid.CreateVersion7(), scope, ct)
            .ConfigureAwait(false);
        return TokenIssueResult.Ok(access, ExpiresInSeconds(), refresh, scope);
    }

    TokenIssueResult IssueClientCredentials(TokenIssueRequest request, IdpClient client)
    {
        if (!TryGrantScopes(request.Scope, client, out var scope, out var error))
            return error!;

        var access = CreateAccessToken(client.Id.ToString("D"), client, scope);
        return TokenIssueResult.Ok(access, ExpiresInSeconds(), refreshToken: null, scope);
    }

    async ValueTask<TokenIssueResult> IssueRefreshAsync(TokenIssueRequest request, IdpClient client, CancellationToken ct)
    {
        await _rotation.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!RefreshTokenFormat.TryParse(request.RefreshToken, out var id, out var secret))
                return TokenIssueResult.Fail(IdpTokenErrors.InvalidGrant);

            var row = await _refresh.TryGetAsync(id, ct).ConfigureAwait(false);
            if (row is null || row.ClientId != client.Id || !RefreshTokenFormat.SecretEquals(row.SecretHash, secret))
                return TokenIssueResult.Fail(IdpTokenErrors.InvalidGrant);

            var now = _time.GetUtcNow();
            if (row.ExpiresUtc <= now)
                return TokenIssueResult.Fail(IdpTokenErrors.InvalidGrant);

            if (row.RevokedUtc is not null)
            {
                await RevokeFamilyAsync(row.FamilyId, ct).ConfigureAwait(false);
                return TokenIssueResult.Fail(IdpTokenErrors.InvalidGrant);
            }

            if (row.AccountId == Guid.Empty)
                return TokenIssueResult.Fail(IdpTokenErrors.InvalidGrant);

            var account = await _accounts.TryGetAsync(new AccountId(row.AccountId), ct).ConfigureAwait(false);
            if (account is null || account.Disabled)
                return TokenIssueResult.Fail(IdpTokenErrors.InvalidGrant);

            if (!TryRefreshScope(request.Scope, row.Scope, client, out var scope, out var error))
                return error!;

            row.RevokedUtc = now;
            var nextId = Guid.CreateVersion7();
            row.ReplacedById = nextId;
            await _refresh.UpsertAsync(row, ct).ConfigureAwait(false);

            var access = CreateAccessToken(account.Id.ToString("D"), client, scope);
            var refresh = await CreateRefreshTokenAsync(account.Id, client.Id, row.FamilyId, scope, ct, nextId)
                .ConfigureAwait(false);
            return TokenIssueResult.Ok(access, ExpiresInSeconds(), refresh, scope);
        }
        finally
        {
            _rotation.Release();
        }
    }

    async ValueTask RevokeFamilyAsync(Guid familyId, CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        var family = await _refresh.FindByFamilyIdAsync(familyId, ct).ConfigureAwait(false);
        foreach (var token in family)
        {
            if (token.RevokedUtc is not null)
                continue;
            token.RevokedUtc = now;
            await _refresh.UpsertAsync(token, ct).ConfigureAwait(false);
        }
    }

    async ValueTask<string> CreateRefreshTokenAsync(
        Guid accountId,
        Guid clientPk,
        Guid familyId,
        string scope,
        CancellationToken ct,
        Guid? id = null)
    {
        var tokenId = id ?? Guid.CreateVersion7();
        var wire = RefreshTokenFormat.Create(tokenId, out var secret);
        var row = new IdpRefreshToken
        {
            Id = tokenId,
            FamilyId = familyId,
            AccountId = accountId,
            ClientId = clientPk,
            SecretHash = RefreshTokenFormat.HashSecret(secret),
            Scope = scope,
            ExpiresUtc = _time.GetUtcNow() + _options.RefreshTokenLifetime,
        };
        await _refresh.UpsertAsync(row, ct).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(secret);
        return wire;
    }

    string CreateAccessToken(string subject, IdpClient client, string scope)
    {
        var audience = ResolveAudience(client);
        var now = _time.GetUtcNow();
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = audience,
            Subject = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, subject),
                new Claim("client_id", client.ClientId),
                new Claim("scope", scope),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.CreateVersion7().ToString("D")),
            ]),
            NotBefore = now.UtcDateTime.AddMinutes(-1),
            Expires = now.UtcDateTime + _options.AccessTokenLifetime,
            SigningCredentials = _keys.GetSigningCredentials(),
        };
        return _handler.CreateToken(descriptor);
    }

    string ResolveAudience(IdpClient client)
    {
        if (client.AllowedAudiences.Count > 0)
            return client.AllowedAudiences[0];
        if (_options.Audiences.Count == 0)
            throw new InvalidOperationException("IdpOptions.Audiences must contain at least one audience.");
        return _options.Audiences[0];
    }

    static bool TryGrantScopes(string? requested, IdpClient client, out string scope, out TokenIssueResult? error)
    {
        error = null;
        var allowed = client.AllowedScopes;
        var asked = string.IsNullOrWhiteSpace(requested)
            ? []
            : requested.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        IEnumerable<string> granted = asked.Length == 0
            ? allowed
            : asked.Where(s => allowed.Contains(s, StringComparer.Ordinal));

        var list = granted.Distinct(StringComparer.Ordinal).ToArray();
        if (asked.Length > 0 && list.Length == 0)
        {
            scope = "";
            error = TokenIssueResult.Fail(IdpTokenErrors.InvalidScope);
            return false;
        }

        scope = string.Join(' ', list);
        return true;
    }

    static bool TryRefreshScope(
        string? requested,
        string original,
        IdpClient client,
        out string scope,
        out TokenIssueResult? error)
    {
        error = null;
        var originalSet = (original ?? "")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.Ordinal);
        if (originalSet.Count == 0)
        {
            scope = "";
            error = TokenIssueResult.Fail(IdpTokenErrors.InvalidScope);
            return false;
        }

        if (string.IsNullOrWhiteSpace(requested))
        {
            scope = string.IsNullOrWhiteSpace(original) ? string.Join(' ', originalSet) : original;
            return true;
        }

        var asked = requested.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var item in asked)
        {
            if (!originalSet.Contains(item) || !client.AllowedScopes.Contains(item, StringComparer.Ordinal))
            {
                scope = "";
                error = TokenIssueResult.Fail(IdpTokenErrors.InvalidScope);
                return false;
            }
        }

        scope = string.Join(' ', asked.Distinct(StringComparer.Ordinal));
        return true;
    }

    int ExpiresInSeconds() => (int)Math.Ceiling(_options.AccessTokenLifetime.TotalSeconds);

    void ValidateDevelopmentGuards()
    {
        if (_options.IsDevelopment)
            return;
        if (_options.AllowEphemeralSigningKey)
            throw new InvalidOperationException(SigningKeyRing.DevelopmentPemForbidden);
    }
}
