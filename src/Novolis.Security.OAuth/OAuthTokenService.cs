using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Novolis.Security.PasswordHashing;

namespace Novolis.Security.OAuth;

/// <summary>Issues ES384 access tokens and rotating refresh tokens for confidential clients.</summary>
public sealed class OAuthTokenService : ITokenService
{
    readonly OAuthOptions _options;
    readonly ICredentialStore _accounts;
    readonly IClientStore _clients;
    readonly IRefreshTokenStore _refresh;
    readonly ICacheStore _cache;
    readonly IEventStore _events;
    readonly PasswordHasher _hasher;
    readonly SigningKeyRing _keys;
    readonly TimeProvider _time;
    readonly JsonWebTokenHandler _handler = new();
    readonly string _dummyHash;
    static readonly HashSet<string> SupportedGrants =
    [
        OAuthGrantTypes.Password,
        OAuthGrantTypes.ClientCredentials,
        OAuthGrantTypes.RefreshToken,
    ];

    /// <summary>Creates the token service.</summary>
    public OAuthTokenService(
        IOptions<OAuthOptions> options,
        ICredentialStore accounts,
        IClientStore clients,
        IRefreshTokenStore refresh,
        ICacheStore cache,
        IEventStore events,
        PasswordHasher hasher,
        SigningKeyRing keys,
        TimeProvider time)
    {
        _options = options.Value;
        _accounts = accounts;
        _clients = clients;
        _refresh = refresh;
        _cache = cache;
        _events = events;
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
            return await DenyAsync(request, OAuthTokenErrors.InvalidRequest, account: null, ct).ConfigureAwait(false);

        if (await IsRateLimitedAsync(request.ClientId, ct).ConfigureAwait(false))
            return await RateLimitedAsync(request, ct).ConfigureAwait(false);

        var client = await AuthenticateClientAsync(request, ct).ConfigureAwait(false);
        if (client is null)
            return await DenyAsync(request, OAuthTokenErrors.InvalidClient, account: null, ct).ConfigureAwait(false);

        if (client.Disabled)
            return await DenyAsync(request, OAuthTokenErrors.InvalidClient, account: null, ct).ConfigureAwait(false);

        if (!client.Confidential)
            return await DenyAsync(request, OAuthTokenErrors.UnauthorizedClient, account: null, ct).ConfigureAwait(false);

        if (!SupportedGrants.Contains(request.GrantType))
            return await DenyAsync(request, OAuthTokenErrors.UnsupportedGrantType, account: null, ct).ConfigureAwait(false);

        if (!client.AllowedGrantTypes.Contains(request.GrantType, StringComparer.Ordinal))
            return await DenyAsync(request, OAuthTokenErrors.UnauthorizedClient, account: null, ct).ConfigureAwait(false);

        TokenIssueResult result = request.GrantType switch
        {
            OAuthGrantTypes.Password => await IssuePasswordAsync(request, client, ct).ConfigureAwait(false),
            OAuthGrantTypes.ClientCredentials => IssueClientCredentials(request, client),
            OAuthGrantTypes.RefreshToken => await IssueRefreshAsync(request, client, ct).ConfigureAwait(false),
            _ => TokenIssueResult.Fail(OAuthTokenErrors.UnsupportedGrantType),
        };

        await ObserveAsync(request, result, request.CredentialReference?.Value, ct).ConfigureAwait(false);
        return result;
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
                GrantType = OAuthGrantTypes.RefreshToken,
                ClientId = clientId,
                ClientSecret = clientSecret,
            },
            ct).ConfigureAwait(false);
        if (client is null || client.Disabled)
            return false;

        if (!RefreshTokenFormat.TryParse(refreshToken, out var id, out var secret))
            return true;

        var row = await _refresh.TryGetAsync(id, ct).ConfigureAwait(false);
        if (row is null || row.ClientId != client.Id || !RefreshTokenFormat.SecretEquals(row.SecretHash, secret))
            return true;

        await RevokeFamilyAsync(row.FamilyId, ct).ConfigureAwait(false);
        return true;
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

    async ValueTask<bool> IsRateLimitedAsync(string? clientId, CancellationToken ct)
    {
        var key = "idp:rate:client:" + (string.IsNullOrWhiteSpace(clientId) ? "_" : clientId);
        var count = await _cache.IncrementAsync(key, _options.TokenAttemptWindow, ct).ConfigureAwait(false);
        return count > _options.TokenAttemptsPerWindow;
    }

    async ValueTask<OAuthClient?> AuthenticateClientAsync(TokenIssueRequest request, CancellationToken ct)
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

    async ValueTask<TokenIssueResult> IssuePasswordAsync(TokenIssueRequest request, OAuthClient client, CancellationToken ct)
    {
        var password = request.Password ?? "";
        if (request.CredentialReference is not { } accountId)
        {
            _hasher.CompareHashedPassword(_dummyHash, password);
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        }

        var failKey = "idp:fail:account:" + accountId.Value.ToString("N", CultureInfo.InvariantCulture);
        if (await _cache.GetAsync(failKey, ct).ConfigureAwait(false) >= _options.PasswordFailuresPerWindow)
        {
            _hasher.CompareHashedPassword(_dummyHash, password);
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        }

        var account = await _accounts.TryGetAsync(accountId, ct).ConfigureAwait(false);
        var hash = account?.PasswordHash ?? _dummyHash;
        var passwordOk = _hasher.CompareHashedPassword(hash, password);
        if (account is null || account.Disabled || !passwordOk)
        {
            await _cache.IncrementAsync(failKey, _options.PasswordFailureWindow, ct).ConfigureAwait(false);
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        }

        if (!TryGrantScopes(request.Scope, client, out var scope, out var error))
            return error!;

        var access = CreateAccessToken(account.Id.ToString("D"), client, scope);
        var refresh = await CreateRefreshTokenAsync(account.Id, client.Id, Guid.CreateVersion7(), scope, ct)
            .ConfigureAwait(false);
        return TokenIssueResult.Ok(access, ExpiresInSeconds(), refresh, scope);
    }

    TokenIssueResult IssueClientCredentials(TokenIssueRequest request, OAuthClient client)
    {
        if (!TryGrantScopes(request.Scope, client, out var scope, out var error))
            return error!;

        var access = CreateAccessToken(client.Id.ToString("D"), client, scope);
        return TokenIssueResult.Ok(access, ExpiresInSeconds(), refreshToken: null, scope);
    }

    async ValueTask<TokenIssueResult> IssueRefreshAsync(TokenIssueRequest request, OAuthClient client, CancellationToken ct)
    {
        if (!RefreshTokenFormat.TryParse(request.RefreshToken, out var id, out var secret))
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);

        var row = await _refresh.TryGetAsync(id, ct).ConfigureAwait(false);
        if (row is null || row.ClientId != client.Id || !RefreshTokenFormat.SecretEquals(row.SecretHash, secret))
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);

        var now = _time.GetUtcNow();
        if (row.ExpiresUtc <= now)
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);

        if (row.RevokedUtc is not null)
        {
            await RevokeFamilyAsync(row.FamilyId, ct).ConfigureAwait(false);
            await ObserveTypeAsync(SecurityEventTypes.RefreshReuse, request, row.CredentialReference, ct).ConfigureAwait(false);
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        }

        if (row.CredentialReference == Guid.Empty)
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);

        var account = await _accounts.TryGetAsync(new CredentialReference(row.CredentialReference), ct).ConfigureAwait(false);
        if (account is null || account.Disabled)
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);

        if (!TryRefreshScope(request.Scope, row.Scope, client, out var scope, out var error))
            return error!;

        var leaseKey = "idp:rotate:" + id.ToString("N", CultureInfo.InvariantCulture);
        var leased = await _cache.TryCreateAsync(leaseKey, _options.RefreshTokenLifetime, ct).ConfigureAwait(false);
        if (!leased)
        {
            await RevokeFamilyAsync(row.FamilyId, ct).ConfigureAwait(false);
            await ObserveTypeAsync(SecurityEventTypes.RefreshReuse, request, row.CredentialReference, ct).ConfigureAwait(false);
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        }

        var nextId = Guid.CreateVersion7();
        var wire = RefreshTokenFormat.Create(nextId, out var nextSecret);
        var next = new RefreshTokenRecord
        {
            Id = nextId,
            FamilyId = row.FamilyId,
            CredentialReference = row.CredentialReference,
            ClientId = client.Id,
            SecretHash = RefreshTokenFormat.HashSecret(nextSecret),
            Scope = scope,
            ExpiresUtc = now + _options.RefreshTokenLifetime,
        };
        CryptographicOperations.ZeroMemory(nextSecret);

        var rotated = await _refresh.TryRotateAsync(id, next, ct).ConfigureAwait(false);
        if (!rotated)
        {
            await RevokeFamilyAsync(row.FamilyId, ct).ConfigureAwait(false);
            await ObserveTypeAsync(SecurityEventTypes.RefreshReuse, request, row.CredentialReference, ct).ConfigureAwait(false);
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        }

        await ObserveTypeAsync(SecurityEventTypes.RefreshRotated, request, row.CredentialReference, ct).ConfigureAwait(false);
        var access = CreateAccessToken(account.Id.ToString("D"), client, scope);
        return TokenIssueResult.Ok(access, ExpiresInSeconds(), wire, scope);
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
        var row = new RefreshTokenRecord
        {
            Id = tokenId,
            FamilyId = familyId,
            CredentialReference = accountId,
            ClientId = clientPk,
            SecretHash = RefreshTokenFormat.HashSecret(secret),
            Scope = scope,
            ExpiresUtc = _time.GetUtcNow() + _options.RefreshTokenLifetime,
        };
        await _refresh.UpsertAsync(row, ct).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(secret);
        return wire;
    }

    string CreateAccessToken(string subject, OAuthClient client, string scope)
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

    string ResolveAudience(OAuthClient client)
    {
        if (client.AllowedAudiences.Count > 0)
            return client.AllowedAudiences[0];
        if (_options.Audiences.Count == 0)
            throw new InvalidOperationException("OAuthOptions.Audiences must contain at least one audience.");
        return _options.Audiences[0];
    }

    static bool TryGrantScopes(string? requested, OAuthClient client, out string scope, out TokenIssueResult? error)
    {
        error = null;
        var allowed = client.AllowedScopes;
        var asked = string.IsNullOrWhiteSpace(requested)
            ? []
            : requested.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (asked.Length == 0)
        {
            scope = string.Join(' ', allowed.Distinct(StringComparer.Ordinal));
            return true;
        }

        foreach (var item in asked)
        {
            if (!allowed.Contains(item, StringComparer.Ordinal))
            {
                scope = "";
                error = TokenIssueResult.Fail(OAuthTokenErrors.InvalidScope);
                return false;
            }
        }

        scope = string.Join(' ', asked.Distinct(StringComparer.Ordinal));
        return true;
    }

    static bool TryRefreshScope(
        string? requested,
        string original,
        OAuthClient client,
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
            error = TokenIssueResult.Fail(OAuthTokenErrors.InvalidScope);
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
                error = TokenIssueResult.Fail(OAuthTokenErrors.InvalidScope);
                return false;
            }
        }

        scope = string.Join(' ', asked.Distinct(StringComparer.Ordinal));
        return true;
    }

    int ExpiresInSeconds() => (int)Math.Ceiling(_options.AccessTokenLifetime.TotalSeconds);

    async ValueTask<TokenIssueResult> DenyAsync(TokenIssueRequest request, string error, Guid? account, CancellationToken ct)
    {
        var result = TokenIssueResult.Fail(error);
        await ObserveAsync(request, result, account, ct).ConfigureAwait(false);
        return result;
    }

    async ValueTask<TokenIssueResult> RateLimitedAsync(TokenIssueRequest request, CancellationToken ct)
    {
        await ObserveTypeAsync(SecurityEventTypes.RateLimited, request, request.CredentialReference?.Value, ct).ConfigureAwait(false);
        return TokenIssueResult.Fail(OAuthTokenErrors.RateLimited);
    }

    async ValueTask ObserveAsync(TokenIssueRequest request, TokenIssueResult result, Guid? accountId, CancellationToken ct)
    {
        var type = result.Succeeded ? SecurityEventTypes.TokenIssued : SecurityEventTypes.TokenDenied;
        await ObserveTypeAsync(type, request, accountId, ct, result.Error).ConfigureAwait(false);
    }

    async ValueTask ObserveTypeAsync(
        string type,
        TokenIssueRequest request,
        Guid? accountId,
        CancellationToken ct,
        string? error = null)
    {
        try
        {
            await _events.RecordAsync(
                new SecurityEvent
                {
                    Utc = _time.GetUtcNow(),
                    Type = type,
                    ClientId = request.ClientId,
                    CredentialReference = accountId,
                    GrantType = request.GrantType,
                    Error = error,
                },
                ct).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Observation must never fail closed on the token path.
        }
    }

    void ValidateDevelopmentGuards()
    {
        if (_options.IsDevelopment)
            return;
        if (_options.AllowEphemeralSigningKey)
            throw new InvalidOperationException(SigningKeyRing.DevelopmentPemForbidden);
    }
}
