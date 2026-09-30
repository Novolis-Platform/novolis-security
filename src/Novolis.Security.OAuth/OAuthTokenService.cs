using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Novolis.Security.Authentication;

namespace Novolis.Security.OAuth;

/// <summary>OAuth authorization-server core for Authorization Code, client credentials, and refresh grants.</summary>
public sealed class OAuthTokenService : ITokenService
{
    readonly OAuthOptions _options;
    readonly IClientStore _clients;
    readonly IAuthorizationCodeStore _codes;
    readonly IRefreshTokenStore _refresh;
    readonly ICacheStore _cache;
    readonly IEventStore _events;
    readonly ClientSecretHasher _clientSecrets;
    readonly SigningKeyRing _keys;
    readonly TimeProvider _time;
    readonly IIdentityStore? _identities;
    readonly JsonWebTokenHandler _handler = new();
    readonly string _dummySecretHash;

    static readonly HashSet<string> SupportedGrants =
    [
        OAuthGrantTypes.AuthorizationCode,
        OAuthGrantTypes.ClientCredentials,
        OAuthGrantTypes.RefreshToken,
    ];

    /// <summary>Creates the OAuth token service.</summary>
    public OAuthTokenService(
        IOptions<OAuthOptions> options,
        IClientStore clients,
        IAuthorizationCodeStore codes,
        IRefreshTokenStore refresh,
        ICacheStore cache,
        IEventStore events,
        ClientSecretHasher clientSecrets,
        SigningKeyRing keys,
        TimeProvider time,
        IIdentityStore? identities = null)
    {
        _options = options.Value;
        _clients = clients;
        _codes = codes;
        _refresh = refresh;
        _cache = cache;
        _events = events;
        _clientSecrets = clientSecrets;
        _keys = keys;
        _time = time;
        _identities = identities;
        _dummySecretHash = clientSecrets.Hash("novolis-oauth-client-timing-dummy");
        ValidateOptions();
    }

    /// <inheritdoc />
    public async ValueTask<TokenIssueResult> IssueAsync(
        TokenIssueRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!SupportedGrants.Contains(request.GrantType))
            return await DenyAsync(request, OAuthTokenErrors.UnsupportedGrantType, cancellationToken)
                .ConfigureAwait(false);

        if (await IsRateLimitedAsync(request.ClientId, cancellationToken).ConfigureAwait(false))
            return await DenyAsync(request, OAuthTokenErrors.RateLimited, cancellationToken)
                .ConfigureAwait(false);

        var client = await AuthenticateClientAsync(request, cancellationToken).ConfigureAwait(false);
        if (client is null)
            return await DenyAsync(request, OAuthTokenErrors.InvalidClient, cancellationToken)
                .ConfigureAwait(false);
        if (client.Disabled)
            return await DenyAsync(request, OAuthTokenErrors.InvalidClient, cancellationToken)
                .ConfigureAwait(false);
        if (!client.AllowedGrantTypes.Contains(request.GrantType, StringComparer.Ordinal))
            return await DenyAsync(request, OAuthTokenErrors.UnauthorizedClient, cancellationToken)
                .ConfigureAwait(false);

        var result = request.GrantType switch
        {
            OAuthGrantTypes.AuthorizationCode => await RedeemAuthorizationCodeAsync(client, request, cancellationToken)
                .ConfigureAwait(false),
            OAuthGrantTypes.ClientCredentials => IssueClientCredentials(client, request.Scope, request.Audience),
            OAuthGrantTypes.RefreshToken => await IssueRefreshAsync(client, request, cancellationToken)
                .ConfigureAwait(false),
            _ => TokenIssueResult.Fail(OAuthTokenErrors.UnsupportedGrantType),
        };

        await ObserveAsync(request, result, result.IdentityId, cancellationToken).ConfigureAwait(false);
        return result;
    }

    /// <summary>Issues a short-lived authorization code after session and request validation.</summary>
    public async ValueTask<AuthorizationCodeIssueResult> IssueAuthorizationCodeAsync(
        AuthorizationCodeIssueRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.IdentityId.Value == Guid.Empty
            || string.IsNullOrWhiteSpace(request.ClientId)
            || string.IsNullOrWhiteSpace(request.RedirectUri)
            || string.IsNullOrWhiteSpace(request.CodeChallenge)
            || !string.Equals(request.CodeChallengeMethod, "S256", StringComparison.Ordinal))
            return AuthorizationCodeIssueResult.Fail(OAuthTokenErrors.InvalidRequest);

        var client = await _clients.FindByClientIdAsync(request.ClientId, cancellationToken).ConfigureAwait(false);
        if (client is null || client.Disabled)
            return AuthorizationCodeIssueResult.Fail(OAuthTokenErrors.InvalidClient);
        if (!client.AllowedGrantTypes.Contains(OAuthGrantTypes.AuthorizationCode, StringComparer.Ordinal))
            return AuthorizationCodeIssueResult.Fail(OAuthTokenErrors.UnauthorizedClient);
        if (!client.AllowedRedirectUris.Contains(request.RedirectUri, StringComparer.Ordinal))
            return AuthorizationCodeIssueResult.Fail(OAuthTokenErrors.InvalidRequest);
        if (!TryGrantScopes(request.Scope, client, out var scope))
            return AuthorizationCodeIssueResult.Fail(OAuthTokenErrors.InvalidScope);
        if (!TryResolveAudience(request.Audience, client, out var audience))
            return AuthorizationCodeIssueResult.Fail(OAuthTokenErrors.InvalidScope);

        var codeId = Guid.CreateVersion7();
        var wire = AuthorizationCodeFormat.Create(codeId, out var secret);
        var now = _time.GetUtcNow();
        await _codes.UpsertAsync(
            new AuthorizationCodeRecord
            {
                Id = codeId,
                SecretHash = AuthorizationCodeFormat.HashSecret(secret),
                ClientId = client.ClientId,
                IdentityId = request.IdentityId,
                RedirectUri = request.RedirectUri,
                CodeChallenge = request.CodeChallenge,
                CodeChallengeMethod = "S256",
                Scope = scope,
                Audience = audience,
                IssuedUtc = now,
                ExpiresUtc = now + _options.AuthorizationCodeLifetime,
            },
            cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(secret);

        await ObserveTypeAsync(
            SecurityEventTypes.AuthorizationCodeIssued,
            request.ClientId,
            request.IdentityId,
            OAuthGrantTypes.AuthorizationCode,
            null,
            cancellationToken).ConfigureAwait(false);
        return AuthorizationCodeIssueResult.Success(wire, scope, audience);
    }

    /// <inheritdoc />
    public async ValueTask<bool> RevokeAsync(
        string token,
        string? clientId,
        string? clientSecret,
        string? tokenTypeHint = null,
        CancellationToken cancellationToken = default)
    {
        var client = await AuthenticateClientAsync(
            new TokenIssueRequest
            {
                GrantType = OAuthGrantTypes.RefreshToken,
                ClientId = clientId,
                ClientSecret = clientSecret,
            },
            cancellationToken).ConfigureAwait(false);
        if (client is null || client.Disabled)
            return false;

        if (!RefreshTokenFormat.TryParse(token, out var tokenId, out var secret))
            return true;

        var row = await _refresh.TryGetAsync(tokenId, cancellationToken).ConfigureAwait(false);
        if (row is null
            || row.ClientId != client.Id
            || !string.Equals(row.ClientPublicId, client.ClientId, StringComparison.Ordinal)
            || !RefreshTokenFormat.SecretEquals(row.SecretHash, secret))
            return true;

        var now = _time.GetUtcNow();
        await _refresh.RevokeFamilyAsync(row.FamilyId, now, cancellationToken).ConfigureAwait(false);
        await ObserveTypeAsync(
            SecurityEventTypes.TokenRevoked,
            client.ClientId,
            row.IdentityId,
            OAuthGrantTypes.RefreshToken,
            null,
            cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <summary>Parameters for validating ES384 access tokens.</summary>
    public TokenValidationParameters CreateValidationParameters() => new()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidateLifetime = true,
        RequireSignedTokens = true,
        RequireExpirationTime = true,
        RequireAudience = true,
        TryAllIssuerSigningKeys = false,
        ValidIssuer = _options.Issuer.ToString(),
        ValidAudiences = _options.Audiences,
        IssuerSigningKeys = _keys.GetValidationKeys(),
        ClockSkew = _options.ClockSkew,
        ValidAlgorithms = [SecurityAlgorithms.EcdsaSha384],
        LifetimeValidator = (notBefore, expires, _, _) =>
        {
            var now = _time.GetUtcNow().UtcDateTime;
            if (notBefore is null || expires is null)
                return false;
            return now + _options.ClockSkew >= notBefore.Value
                && now - _options.ClockSkew < expires.Value;
        },
    };

    /// <summary>Public JWKS projection.</summary>
    public JsonWebKeySet GetJsonWebKeySet() => _keys.GetJsonWebKeySet();

    /// <summary>Validates an access token using issuer, audience, ES384, and lifetime checks.</summary>
    public async ValueTask<TokenValidationResult> ValidateAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        return await _handler.ValidateTokenAsync(token, CreateValidationParameters()).ConfigureAwait(false);
    }

    async ValueTask<TokenIssueResult> RedeemAuthorizationCodeAsync(
        OAuthClient client,
        TokenIssueRequest request,
        CancellationToken cancellationToken)
    {
        if (!AuthorizationCodeFormat.TryParse(request.AuthorizationCode, out var codeId, out var secret)
            || string.IsNullOrWhiteSpace(request.RedirectUri)
            || string.IsNullOrWhiteSpace(request.CodeVerifier))
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);

        var challenge = ComputeS256(request.CodeVerifier);
        var consumed = await _codes.TryConsumeAsync(
            codeId,
            AuthorizationCodeFormat.HashSecret(secret),
            client.ClientId,
            request.RedirectUri,
            challenge,
            _time.GetUtcNow(),
            cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(secret);
        if (!consumed.Succeeded || consumed.Record is null)
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);

        var record = consumed.Record;
        if (_identities is not null)
        {
            var identity = await _identities.TryGetAsync(record.IdentityId, cancellationToken).ConfigureAwait(false);
            if (identity is null || identity.Disabled)
                return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        }

        var access = CreateAccessToken(record.IdentityId, client, record.Scope, record.Audience);
        var refresh = await CreateRefreshTokenAsync(
            record.IdentityId,
            client,
            record.Scope,
            record.Audience,
            cancellationToken).ConfigureAwait(false);
        await ObserveTypeAsync(
            SecurityEventTypes.AuthorizationCodeRedeemed,
            client.ClientId,
            record.IdentityId,
            OAuthGrantTypes.AuthorizationCode,
            null,
            cancellationToken).ConfigureAwait(false);
        return TokenIssueResult.Ok(access, ExpiresInSeconds(), refresh, record.Scope, record.IdentityId);
    }

    TokenIssueResult IssueClientCredentials(OAuthClient client, string? requestedScope, string? requestedAudience)
    {
        if (client.ClientType != OAuthClientType.Confidential)
            return TokenIssueResult.Fail(OAuthTokenErrors.UnauthorizedClient);
        if (!TryGrantScopes(requestedScope, client, out var scope)
            || !TryResolveAudience(requestedAudience, client, out var audience))
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidScope);

        var access = CreateAccessToken(null, client, scope, audience);
        return TokenIssueResult.Ok(access, ExpiresInSeconds(), null, scope, null);
    }

    async ValueTask<TokenIssueResult> IssueRefreshAsync(
        OAuthClient client,
        TokenIssueRequest request,
        CancellationToken cancellationToken)
    {
        if (client.ClientType != OAuthClientType.Confidential
            && string.IsNullOrWhiteSpace(request.ClientSecret))
        {
            // Public clients may rotate refresh tokens without an embedded static secret.
        }

        if (!RefreshTokenFormat.TryParse(request.RefreshToken, out var tokenId, out var secret))
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);

        var row = await _refresh.TryGetAsync(tokenId, cancellationToken).ConfigureAwait(false);
        if (row is null
            || row.ClientId != client.Id
            || !string.Equals(row.ClientPublicId, client.ClientId, StringComparison.Ordinal)
            || !RefreshTokenFormat.SecretEquals(row.SecretHash, secret))
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);

        var now = _time.GetUtcNow();
        if (row.ExpiresUtc <= now)
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        if (row.RevokedUtc is not null)
        {
            await _refresh.RevokeFamilyAsync(row.FamilyId, now, cancellationToken).ConfigureAwait(false);
            await ObserveTypeAsync(
                SecurityEventTypes.RefreshReuseDetected,
                client.ClientId,
                row.IdentityId,
                OAuthGrantTypes.RefreshToken,
                OAuthTokenErrors.InvalidGrant,
                cancellationToken).ConfigureAwait(false);
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        }

        if (_identities is not null)
        {
            var identity = await _identities.TryGetAsync(row.IdentityId, cancellationToken).ConfigureAwait(false);
            if (identity is null || identity.Disabled)
                return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        }

        if (!TryRefreshScope(request.Scope, row.Scope, client, out var scope))
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidScope);
        if (!string.IsNullOrWhiteSpace(request.Audience)
            && !string.Equals(request.Audience, row.Audience, StringComparison.Ordinal))
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidScope);

        var nextId = Guid.CreateVersion7();
        var wire = RefreshTokenFormat.Create(nextId, out var nextSecret);
        var replacement = new RefreshTokenRecord
        {
            Id = nextId,
            FamilyId = row.FamilyId,
            IdentityId = row.IdentityId,
            ClientId = client.Id,
            ClientPublicId = client.ClientId,
            SecretHash = RefreshTokenFormat.HashSecret(nextSecret),
            Scope = scope,
            Audience = row.Audience,
            CreatedUtc = now,
            ExpiresUtc = now + _options.RefreshTokenLifetime,
        };
        CryptographicOperations.ZeroMemory(secret);
        CryptographicOperations.ZeroMemory(nextSecret);

        var rotated = await _refresh.TryRotateAsync(
            tokenId,
            replacement,
            now,
            cancellationToken).ConfigureAwait(false);
        if (!rotated.Succeeded)
        {
            if (rotated.WasReplayed)
                await _refresh.RevokeFamilyAsync(row.FamilyId, now, cancellationToken).ConfigureAwait(false);
            await ObserveTypeAsync(
                SecurityEventTypes.RefreshReuseDetected,
                client.ClientId,
                row.IdentityId,
                OAuthGrantTypes.RefreshToken,
                OAuthTokenErrors.InvalidGrant,
                cancellationToken).ConfigureAwait(false);
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        }

        var access = CreateAccessToken(row.IdentityId, client, scope, row.Audience);
        await ObserveTypeAsync(
            SecurityEventTypes.RefreshTokenRotated,
            client.ClientId,
            row.IdentityId,
            OAuthGrantTypes.RefreshToken,
            null,
            cancellationToken).ConfigureAwait(false);
        return TokenIssueResult.Ok(access, ExpiresInSeconds(), wire, scope, row.IdentityId);
    }

    async ValueTask<string> CreateRefreshTokenAsync(
        IdentityId identityId,
        OAuthClient client,
        string scope,
        string audience,
        CancellationToken cancellationToken)
    {
        var id = Guid.CreateVersion7();
        var familyId = Guid.CreateVersion7();
        var wire = RefreshTokenFormat.Create(id, out var secret);
        var now = _time.GetUtcNow();
        await _refresh.UpsertAsync(
            new RefreshTokenRecord
            {
                Id = id,
                FamilyId = familyId,
                IdentityId = identityId,
                ClientId = client.Id,
                ClientPublicId = client.ClientId,
                SecretHash = RefreshTokenFormat.HashSecret(secret),
                Scope = scope,
                Audience = audience,
                CreatedUtc = now,
                ExpiresUtc = now + _options.RefreshTokenLifetime,
            },
            cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(secret);
        return wire;
    }

    string CreateAccessToken(
        IdentityId? identityId,
        OAuthClient client,
        string scope,
        string audience)
    {
        var now = _time.GetUtcNow();
        var subject = identityId?.ToString() ?? client.ClientId;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer.ToString(),
            Audience = audience,
            Subject = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, subject),
                new Claim("client_id", client.ClientId),
                new Claim("scope", scope),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.CreateVersion7().ToString("D")),
            ]),
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = (now + _options.AccessTokenLifetime).UtcDateTime,
            SigningCredentials = _keys.GetSigningCredentials(),
        };
        return _handler.CreateToken(descriptor);
    }

    async ValueTask<OAuthClient?> AuthenticateClientAsync(
        TokenIssueRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.ClientId))
            return null;

        var client = await _clients.FindByClientIdAsync(request.ClientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
        {
            _clientSecrets.Verify(_dummySecretHash, request.ClientSecret ?? "");
            return null;
        }

        if (client.ClientType == OAuthClientType.Public)
            return string.IsNullOrEmpty(request.ClientSecret) ? client : null;

        if (string.IsNullOrEmpty(request.ClientSecret)
            || !_clientSecrets.Verify(client.SecretHash, request.ClientSecret))
            return null;
        return client;
    }

    async ValueTask<bool> IsRateLimitedAsync(string? clientId, CancellationToken cancellationToken)
    {
        var key = "oauth:rate:client:" + (string.IsNullOrWhiteSpace(clientId) ? "_" : clientId);
        var count = await _cache.IncrementAsync(key, _options.TokenAttemptWindow, cancellationToken)
            .ConfigureAwait(false);
        return count > _options.TokenAttemptsPerWindow;
    }

    static bool TryGrantScopes(string? requested, OAuthClient client, out string scope)
    {
        var allowed = client.AllowedScopes;
        var asked = Split(requested);
        if (asked.Length == 0)
        {
            scope = string.Join(' ', allowed.Distinct(StringComparer.Ordinal));
            return true;
        }

        if (asked.Any(item => !allowed.Contains(item, StringComparer.Ordinal)))
        {
            scope = "";
            return false;
        }

        scope = string.Join(' ', asked.Distinct(StringComparer.Ordinal));
        return true;
    }

    static bool TryRefreshScope(string? requested, string original, OAuthClient client, out string scope)
    {
        var originalSet = Split(original).ToHashSet(StringComparer.Ordinal);
        var asked = Split(requested);
        if (asked.Length == 0)
        {
            scope = original;
            return true;
        }

        if (asked.Any(item => !originalSet.Contains(item) || !client.AllowedScopes.Contains(item, StringComparer.Ordinal)))
        {
            scope = "";
            return false;
        }

        scope = string.Join(' ', asked.Distinct(StringComparer.Ordinal));
        return true;
    }

    bool TryResolveAudience(string? requested, OAuthClient client, out string audience)
    {
        var allowed = client.AllowedAudiences.Count > 0
            ? client.AllowedAudiences
            : _options.Audiences;
        if (allowed.Count == 0)
        {
            audience = "";
            return false;
        }

        if (string.IsNullOrWhiteSpace(requested))
        {
            audience = allowed[0];
            return true;
        }

        if (!allowed.Contains(requested, StringComparer.Ordinal))
        {
            audience = "";
            return false;
        }

        audience = requested;
        return true;
    }

    static string[] Split(string? value) => string.IsNullOrWhiteSpace(value)
        ? []
        : value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    static string ComputeS256(string verifier)
    {
        var bytes = Encoding.ASCII.GetBytes(verifier);
        return Base64UrlEncoder.Encode(SHA256.HashData(bytes));
    }

    int ExpiresInSeconds() => (int)Math.Ceiling(_options.AccessTokenLifetime.TotalSeconds);

    async ValueTask<TokenIssueResult> DenyAsync(
        TokenIssueRequest request,
        string error,
        CancellationToken cancellationToken)
    {
        var result = TokenIssueResult.Fail(error);
        await ObserveAsync(request, result, null, cancellationToken).ConfigureAwait(false);
        return result;
    }

    async ValueTask ObserveAsync(
        TokenIssueRequest request,
        TokenIssueResult result,
        IdentityId? identityId,
        CancellationToken cancellationToken)
    {
        await ObserveTypeAsync(
            result.Succeeded ? SecurityEventTypes.TokenIssued : SecurityEventTypes.TokenDenied,
            request.ClientId,
            identityId,
            request.GrantType,
            result.Error,
            cancellationToken).ConfigureAwait(false);
    }

    async ValueTask ObserveTypeAsync(
        string type,
        string? clientId,
        IdentityId? identityId,
        string? grantType,
        string? error,
        CancellationToken cancellationToken)
    {
        try
        {
            await _events.RecordAsync(
                new SecurityEvent
                {
                    Utc = _time.GetUtcNow(),
                    Type = type,
                    ClientId = clientId,
                    IdentityId = identityId,
                    GrantType = grantType,
                    Error = error,
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Security observations cannot make a successful state transition fail.
        }
    }

    void ValidateOptions()
    {
        if (_options.Issuer is null || !_options.Issuer.IsAbsoluteUri)
            throw new InvalidOperationException("OAuthOptions.Issuer must be an absolute URI.");
        if (_options.IsDevelopment)
            return;
        if (_options.AllowEphemeralSigningKey)
            throw new InvalidOperationException(SigningKeyRing.DevelopmentPemForbidden);
    }
}