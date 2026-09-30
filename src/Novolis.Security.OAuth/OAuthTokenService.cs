using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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

        if (await IsRateLimitedAsync(request, cancellationToken).ConfigureAwait(false))
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

        var sender = await ResolveSenderAsync(request, cancellationToken).ConfigureAwait(false);
        if (!sender.Succeeded)
            return await DenyAsync(request, OAuthTokenErrors.InvalidRequest, cancellationToken)
                .ConfigureAwait(false);

        var result = request.GrantType switch
        {
            OAuthGrantTypes.AuthorizationCode => await RedeemAuthorizationCodeAsync(client, request, sender, cancellationToken)
                .ConfigureAwait(false),
            OAuthGrantTypes.ClientCredentials => IssueClientCredentials(client, request.Scope, request.Audience, sender),
            OAuthGrantTypes.RefreshToken => await IssueRefreshAsync(client, request, sender, cancellationToken)
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

    /// <summary>Validates an access token using issuer, audience, ES384, lifetime, confirmation, and revocation checks.</summary>
    public ValueTask<TokenValidationResult> ValidateAsync(
        string token,
        CancellationToken cancellationToken = default) =>
        ValidateAsync(token, proof: null, cancellationToken);

    /// <summary>Validates an access token and, when the token is sender-constrained, the matching proof.</summary>
    public async ValueTask<TokenValidationResult> ValidateAsync(
        string token,
        TokenProofContext? proof,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        var validated = await _handler.ValidateTokenAsync(token, CreateValidationParameters()).ConfigureAwait(false);
        if (!validated.IsValid || validated.SecurityToken is not JsonWebToken jwt)
            return validated;

        if (await _cache.GetAsync("oauth:deny-jti:" + jwt.Id, cancellationToken).ConfigureAwait(false) > 0)
            return Invalid("Token has been revoked.");

        if (IdentityId.TryParse(jwt.Subject, out var identityId))
        {
            var cutoff = await _cache.GetAsync("oauth:nbf:" + identityId, cancellationToken).ConfigureAwait(false);
            if (cutoff > 0)
            {
                var issued = new DateTimeOffset(DateTime.SpecifyKind(jwt.IssuedAt, DateTimeKind.Utc)).ToUnixTimeSeconds();
                if (issued <= cutoff)
                    return Invalid("Token was issued before identity revocation.");
            }
        }

        if (!TryReadConfirmation(jwt, out var cnf))
            return Invalid("Access token is not sender-constrained.");

        if (cnf.TryGetProperty("jkt", out var jktElement))
        {
            if (proof?.DPoPProof is null)
                return Invalid("DPoP proof is required.");
            var dpop = await DPoPProof.ValidateAsync(
                proof.DPoPProof,
                proof.HttpMethod,
                proof.HttpUri,
                _time,
                _options.ClockSkew,
                token).ConfigureAwait(false);
            if (!dpop.Succeeded
                || !string.Equals(dpop.Jkt, jktElement.GetString(), StringComparison.Ordinal)
                || !await _cache.TryCreateAsync("oauth:dpop:" + dpop.Jti, _options.AccessTokenLifetime, cancellationToken)
                    .ConfigureAwait(false))
                return Invalid("DPoP proof is invalid.");
        }
        else if (cnf.TryGetProperty("x5t#S256", out var x5tElement))
        {
            if (!string.Equals(proof?.CertificateThumbprintSha256, x5tElement.GetString(), StringComparison.Ordinal))
                return Invalid("Client certificate thumbprint does not match.");
        }
        else
        {
            return Invalid("Access token confirmation is incomplete.");
        }

        return validated;
    }

    static TokenValidationResult Invalid(string message) =>
        new() { IsValid = false, Exception = new SecurityTokenValidationException(message) };

    static bool TryReadConfirmation(JsonWebToken jwt, out JsonElement cnf)
    {
        if (jwt.TryGetPayloadValue("cnf", out JsonElement element)
            && element.ValueKind == JsonValueKind.Object)
        {
            cnf = element.Clone();
            return true;
        }

        if (jwt.TryGetPayloadValue("cnf", out string? json)
            && !string.IsNullOrWhiteSpace(json))
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                cnf = document.RootElement.Clone();
                return true;
            }
        }

        cnf = default;
        return false;
    }

    async ValueTask<TokenIssueResult> RedeemAuthorizationCodeAsync(
        OAuthClient client,
        TokenIssueRequest request,
        SenderBinding sender,
        CancellationToken cancellationToken)
    {
        if (!AuthorizationCodeFormat.TryParse(request.AuthorizationCode, out var codeId, out var secret)
            || string.IsNullOrWhiteSpace(request.RedirectUri)
            || string.IsNullOrWhiteSpace(request.CodeVerifier))
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);

        var leased = await _cache.TryCreateAsync(
            "oauth:code:" + codeId.ToString("N"),
            _options.AuthorizationCodeLifetime,
            cancellationToken).ConfigureAwait(false);
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
        if (!consumed.Succeeded || consumed.Record is null || !leased)
        {
            if (consumed.WasReplayed)
                await RevokeCodeIssuanceAsync(consumed.Record, cancellationToken).ConfigureAwait(false);
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        }

        var record = consumed.Record;
        if (_identities is not null)
        {
            var identity = await _identities.TryGetAsync(record.IdentityId, cancellationToken).ConfigureAwait(false);
            if (identity is null || identity.Disabled)
                return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        }

        var access = CreateAccessToken(record.IdentityId, client, record.Scope, record.Audience, sender);
        var refresh = await CreateRefreshTokenAsync(
            record.IdentityId,
            client,
            record.Scope,
            record.Audience,
            sender,
            cancellationToken).ConfigureAwait(false);
        record.AccessTokenJti = access.Jti;
        record.RefreshFamilyId = refresh.FamilyId;
        await _codes.UpsertAsync(record, cancellationToken).ConfigureAwait(false);
        await ObserveTypeAsync(
            SecurityEventTypes.AuthorizationCodeRedeemed,
            client.ClientId,
            record.IdentityId,
            OAuthGrantTypes.AuthorizationCode,
            null,
            cancellationToken).ConfigureAwait(false);
        return TokenIssueResult.Ok(access.Token, ExpiresInSeconds(), refresh.Wire, record.Scope, record.IdentityId);
    }

    TokenIssueResult IssueClientCredentials(
        OAuthClient client,
        string? requestedScope,
        string? requestedAudience,
        SenderBinding sender)
    {
        if (client.ClientType != OAuthClientType.Confidential)
            return TokenIssueResult.Fail(OAuthTokenErrors.UnauthorizedClient);
        if (!TryGrantScopes(requestedScope, client, out var scope)
            || !TryResolveAudience(requestedAudience, client, out var audience))
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidScope);

        var access = CreateAccessToken(null, client, scope, audience, sender);
        return TokenIssueResult.Ok(access.Token, ExpiresInSeconds(), null, scope, null);
    }

    async ValueTask<TokenIssueResult> IssueRefreshAsync(
        OAuthClient client,
        TokenIssueRequest request,
        SenderBinding sender,
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
        var familyExpires = row.FamilyExpiresUtc == default
            ? row.CreatedUtc + _options.RefreshTokenLifetime
            : row.FamilyExpiresUtc;
        if (row.ExpiresUtc <= now || familyExpires <= now)
            return TokenIssueResult.Fail(OAuthTokenErrors.InvalidGrant);
        if (!SenderMatches(row, sender))
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
            ExpiresUtc = Min(now + _options.RefreshTokenLifetime, familyExpires),
            FamilyExpiresUtc = familyExpires,
            CnfJkt = row.CnfJkt,
            CnfX5tS256 = row.CnfX5tS256,
        };
        CryptographicOperations.ZeroMemory(secret);
        CryptographicOperations.ZeroMemory(nextSecret);

        var leased = await _cache.TryCreateAsync(
            "oauth:rotate:" + tokenId.ToString("N"),
            _options.AccessTokenLifetime,
            cancellationToken).ConfigureAwait(false);
        if (!leased)
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

        var access = CreateAccessToken(row.IdentityId, client, scope, row.Audience, sender);
        await ObserveTypeAsync(
            SecurityEventTypes.RefreshTokenRotated,
            client.ClientId,
            row.IdentityId,
            OAuthGrantTypes.RefreshToken,
            null,
            cancellationToken).ConfigureAwait(false);
        return TokenIssueResult.Ok(access.Token, ExpiresInSeconds(), wire, scope, row.IdentityId);
    }

    async ValueTask<(string Wire, Guid FamilyId)> CreateRefreshTokenAsync(
        IdentityId identityId,
        OAuthClient client,
        string scope,
        string audience,
        SenderBinding sender,
        CancellationToken cancellationToken)
    {
        var id = Guid.CreateVersion7();
        var familyId = Guid.CreateVersion7();
        var wire = RefreshTokenFormat.Create(id, out var secret);
        var now = _time.GetUtcNow();
        var familyExpires = now + _options.RefreshTokenLifetime;
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
                ExpiresUtc = familyExpires,
                FamilyExpiresUtc = familyExpires,
                CnfJkt = sender.Jkt,
                CnfX5tS256 = sender.X5tS256,
            },
            cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(secret);
        return (wire, familyId);
    }

    (string Token, string Jti) CreateAccessToken(
        IdentityId? identityId,
        OAuthClient client,
        string scope,
        string audience,
        SenderBinding sender)
    {
        var now = _time.GetUtcNow();
        var subject = identityId?.ToString() ?? client.ClientId;
        var jti = Guid.CreateVersion7().ToString("D");
        var cnf = sender.Jkt is not null
            ? "{\"jkt\":\"" + sender.Jkt + "\"}"
            : "{\"x5t#S256\":\"" + sender.X5tS256 + "\"}";
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer.ToString(),
            Audience = audience,
            Subject = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, subject),
                new Claim("client_id", client.ClientId),
                new Claim("scope", scope),
                new Claim(JwtRegisteredClaimNames.Jti, jti),
                new Claim("cnf", cnf, "JSON"),
            ]),
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = (now + _options.AccessTokenLifetime).UtcDateTime,
            SigningCredentials = _keys.GetSigningCredentials(),
        };
        return (_handler.CreateToken(descriptor), jti);
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

    async ValueTask<bool> IsRateLimitedAsync(TokenIssueRequest request, CancellationToken cancellationToken)
    {
        var clientKey = "oauth:rate:client:" + (string.IsNullOrWhiteSpace(request.ClientId) ? "_" : request.ClientId);
        var clientCount = await _cache.IncrementAsync(clientKey, _options.TokenAttemptWindow, cancellationToken)
            .ConfigureAwait(false);
        if (clientCount > _options.TokenAttemptsPerWindow)
            return true;

        if (string.IsNullOrWhiteSpace(request.RemoteAddress))
            return false;

        var ipCount = await _cache.IncrementAsync(
            "oauth:rate:ip:" + request.RemoteAddress,
            _options.TokenAttemptWindow,
            cancellationToken).ConfigureAwait(false);
        return ipCount > _options.TokenAttemptsPerWindow;
    }

    async ValueTask<SenderBinding> ResolveSenderAsync(TokenIssueRequest request, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(request.CertificateThumbprintSha256)
            && string.IsNullOrWhiteSpace(request.DPoPProof))
            return SenderBinding.FromCertificate(request.CertificateThumbprintSha256);

        if (string.IsNullOrWhiteSpace(request.DPoPProof))
            return SenderBinding.Fail();

        var proof = await DPoPProof.ValidateAsync(
            request.DPoPProof,
            request.HttpMethod,
            string.IsNullOrWhiteSpace(request.HttpUri) ? _options.Issuer.ToString().TrimEnd('/') + "/oauth/token" : request.HttpUri,
            _time,
            _options.ClockSkew).ConfigureAwait(false);
        if (!proof.Succeeded || proof.Jkt is null || proof.Jti is null)
            return SenderBinding.Fail();
        if (!await _cache.TryCreateAsync("oauth:dpop:" + proof.Jti, _options.AccessTokenLifetime, cancellationToken)
                .ConfigureAwait(false))
            return SenderBinding.Fail();
        return SenderBinding.FromDPoP(proof.Jkt);
    }

    static bool SenderMatches(RefreshTokenRecord row, SenderBinding sender)
    {
        if (row.CnfJkt is not null)
            return string.Equals(row.CnfJkt, sender.Jkt, StringComparison.Ordinal);
        if (row.CnfX5tS256 is not null)
            return string.Equals(row.CnfX5tS256, sender.X5tS256, StringComparison.Ordinal);
        return sender.Succeeded;
    }

    async ValueTask RevokeCodeIssuanceAsync(AuthorizationCodeRecord? record, CancellationToken cancellationToken)
    {
        if (record is null)
            return;
        var now = _time.GetUtcNow();
        if (record.RefreshFamilyId is Guid familyId)
            await _refresh.RevokeFamilyAsync(familyId, now, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(record.AccessTokenJti))
        {
            await _cache.SetAsync(
                "oauth:deny-jti:" + record.AccessTokenJti,
                1,
                _options.AccessTokenLifetime + _options.ClockSkew,
                cancellationToken).ConfigureAwait(false);
        }
    }

    static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right) =>
        left <= right ? left : right;

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
        if (_options.AllowInMemoryStores)
            return;
        if (_cache.IsProcessLocal
            || _clients is InMemoryClientStore
            || _codes is InMemoryAuthorizationCodeStore
            || _refresh is InMemoryRefreshTokenStore
            || _events is NoopEventStore)
            throw new InvalidOperationException(
                "Production OAuth hosts must replace in-memory stores and the no-op event sink, or set AllowInMemoryStores.");
    }
}