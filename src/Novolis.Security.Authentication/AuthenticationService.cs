using Microsoft.Extensions.Options;
using Novolis.Security.PasswordHashing;

namespace Novolis.Security.Authentication;

/// <summary>Default high-level authentication façade.</summary>
public sealed class AuthenticationService : IAuthenticationService
{
    readonly IIdentityStore _identities;
    readonly ICredentialStore _credentials;
    readonly IAuthenticationSessionStore _sessions;
    readonly IAuthenticationEventSink _events;
    readonly PasswordHasher _hasher;
    readonly AuthenticationOptions _options;
    readonly TimeProvider _time;
    readonly string _dummyHash;

    /// <summary>Creates the authentication façade.</summary>
    public AuthenticationService(
        IIdentityStore identities,
        ICredentialStore credentials,
        IAuthenticationSessionStore sessions,
        IAuthenticationEventSink events,
        PasswordHasher hasher,
        IOptions<AuthenticationOptions> options,
        TimeProvider time)
    {
        _identities = identities;
        _credentials = credentials;
        _sessions = sessions;
        _events = events;
        _hasher = hasher;
        _options = options.Value;
        _time = time;
        _dummyHash = hasher.HashPassword("novolis-authentication-timing-dummy");
    }

    /// <inheritdoc />
    public async ValueTask<SignInResult> SignInAsync(
        string identifier,
        string password,
        bool createSession = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identifier);
        ArgumentNullException.ThrowIfNull(password);

        var identity = await _identities.FindByIdentifierAsync(identifier, cancellationToken)
            .ConfigureAwait(false);
        var credential = identity is null
            ? null
            : await _credentials.TryGetAsync(identity.CredentialReference, cancellationToken)
                .ConfigureAwait(false);

        var hash = credential?.PasswordHash ?? _dummyHash;
        var passwordMatches = _hasher.CompareHashedPassword(hash, password);
        if (identity is null || credential is null || identity.Disabled || credential.Disabled || !passwordMatches)
        {
            await ObserveAsync(
                AuthenticationEventTypes.SignInFailed,
                identity?.Id,
                "identifier",
                "invalid_credentials",
                cancellationToken).ConfigureAwait(false);
            return SignInResult.Fail();
        }

        string? sessionId = null;
        if (createSession && _options.CreateSessionByDefault)
        {
            var now = _time.GetUtcNow();
            var session = await _sessions.CreateAsync(
                identity.Id,
                now,
                now + _options.SessionLifetime,
                cancellationToken).ConfigureAwait(false);
            sessionId = session.SessionId;

            await ObserveAsync(
                AuthenticationEventTypes.SessionCreated,
                identity.Id,
                null,
                null,
                cancellationToken).ConfigureAwait(false);
        }

        await ObserveAsync(
            AuthenticationEventTypes.SignInSucceeded,
            identity.Id,
            "identifier",
            null,
            cancellationToken).ConfigureAwait(false);
        return SignInResult.Success(identity.Id, sessionId);
    }

    /// <inheritdoc />
    public async ValueTask<SignInResult> RegisterAsync(
        string identifier,
        string password,
        string? displayName = null,
        bool createSession = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var existing = await _identities.FindByIdentifierAsync(identifier, cancellationToken)
            .ConfigureAwait(false);
        if (existing is not null)
        {
            await ObserveAsync(
                AuthenticationEventTypes.SignInFailed,
                existing.Id,
                "identifier",
                "identifier_in_use",
                cancellationToken).ConfigureAwait(false);
            return SignInResult.Fail("identifier_in_use");
        }

        var now = _time.GetUtcNow();
        var reference = CredentialReference.New();
        await _credentials.UpsertAsync(
            new CredentialRecord
            {
                StorageId = Guid.NewGuid(),
                Reference = reference,
                PasswordHash = _hasher.HashPassword(password),
                CreatedUtc = now,
                UpdatedUtc = now,
            },
            cancellationToken).ConfigureAwait(false);

        var identity = new IdentityRecord
        {
            Id = IdentityId.New(),
            CredentialReference = reference,
            Username = identifier.Contains('@', StringComparison.Ordinal) ? null : identifier,
            Email = identifier.Contains('@', StringComparison.Ordinal) ? identifier : null,
            DisplayName = displayName,
            CreatedUtc = now,
        };
        await _identities.UpsertAsync(identity, cancellationToken).ConfigureAwait(false);
        return await SignInAsync(identifier, password, createSession, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask SignOutAsync(
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
            return;

        var session = await _sessions.TryGetAsync(sessionId, cancellationToken).ConfigureAwait(false);
        await _sessions.RevokeAsync(sessionId, _time.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        await ObserveAsync(
            AuthenticationEventTypes.SessionRevoked,
            session?.IdentityId,
            null,
            null,
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<IdentityId?> GetAuthenticatedIdentityAsync(
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
            return null;

        var session = await _sessions.TryGetAsync(sessionId, cancellationToken).ConfigureAwait(false);
        return session is not null && session.IsActive(_time.GetUtcNow())
            ? session.IdentityId
            : null;
    }

    async ValueTask ObserveAsync(
        string type,
        IdentityId? identityId,
        string? identifierType,
        string? error,
        CancellationToken cancellationToken)
    {
        try
        {
            await _events.RecordAsync(
                new AuthenticationSecurityEvent
                {
                    Utc = _time.GetUtcNow(),
                    Type = type,
                    IdentityId = identityId,
                    IdentifierType = identifierType,
                    Error = error,
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Observability must not make authentication state inconsistent.
        }
    }
}
