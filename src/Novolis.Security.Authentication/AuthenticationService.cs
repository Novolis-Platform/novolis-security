using Microsoft.Extensions.Options;
using Novolis.Security.PasswordHashing;
using System.Security.Cryptography;
using System.Text;

namespace Novolis.Security.Authentication;

/// <summary>Default high-level authentication façade.</summary>
public sealed class AuthenticationService : IAuthenticationService
{
    /// <summary>Library floor for <see cref="RegisterAsync"/>. Options cannot go below this.</summary>
    public const int AbsoluteMinimumPasswordLength = 8;

    readonly IIdentityStore _identities;
    readonly ICredentialStore _credentials;
    readonly IAuthenticationSessionStore _sessions;
    readonly IAuthenticationEventSink _events;
    readonly IPasswordBreachChecker? _breachChecker;
    readonly IMfaProvider _mfa;
    readonly ICacheStore _cache;
    readonly IEnumerable<IIdentityRevocation> _revocations;
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
        TimeProvider time,
        ICacheStore cache,
        IMfaProvider? mfa = null,
        IPasswordBreachChecker? breachChecker = null,
        IEnumerable<IIdentityRevocation>? revocations = null)
    {
        _identities = identities;
        _credentials = credentials;
        _sessions = sessions;
        _events = events;
        _hasher = hasher;
        _options = options.Value;
        _time = time;
        _cache = cache;
        _mfa = mfa ?? NoopMfaProvider.Instance;
        _breachChecker = breachChecker;
        _revocations = revocations ?? [];
        _dummyHash = hasher.HashPassword("novolis-authentication-timing-dummy");
    }

    /// <inheritdoc />
    public async ValueTask<SignInResult> SignInAsync(
        string identifier,
        string password,
        bool createSession = true,
        string? mfaProof = null,
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

        var locked = credential is not null
            && await IsLockedAsync(credential, cancellationToken).ConfigureAwait(false);
        var hash = credential is null || locked ? _dummyHash : credential.PasswordHash;
        var passwordMatches = _hasher.CompareHashedPassword(hash, password);
        if (identity is null || credential is null || identity.Disabled || locked || !passwordMatches)
        {
            if (credential is not null && identity is not null && !identity.Disabled && !locked)
                await RecordFailureAsync(credential, identity.Id, cancellationToken).ConfigureAwait(false);
            else if (credential is null)
                await RecordUnknownFailureAsync(identifier, cancellationToken).ConfigureAwait(false);

            await ObserveAsync(
                AuthenticationEventTypes.SignInFailed,
                identity?.Id,
                "identifier",
                "invalid_credentials",
                cancellationToken).ConfigureAwait(false);
            return SignInResult.Fail();
        }

        return await FinishSignInAsync(
            identity,
            credential,
            createSession,
            requireMfa: true,
            mfaProof,
            cancellationToken).ConfigureAwait(false);
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

        var policyError = await ValidateNewPasswordAsync(password, identifier, cancellationToken)
            .ConfigureAwait(false);
        if (policyError is not null)
            return SignInResult.Fail(policyError);

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
        var credential = new CredentialRecord
        {
            StorageId = Guid.NewGuid(),
            Reference = reference,
            PasswordHash = _hasher.HashPassword(password),
            CreatedUtc = now,
            UpdatedUtc = now,
        };
        await _credentials.UpsertAsync(credential, cancellationToken).ConfigureAwait(false);

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
        return await FinishSignInAsync(
            identity,
            credential,
            createSession,
            requireMfa: false,
            mfaProof: null,
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask SignOutAsync(
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
            return;

        var session = await _sessions.TryGetAsync(sessionId, cancellationToken).ConfigureAwait(false);
        var now = _time.GetUtcNow();
        await _sessions.RevokeAsync(sessionId, now, cancellationToken).ConfigureAwait(false);
        if (session is not null)
            await NotifyRevocationAsync(session.IdentityId, now, cancellationToken).ConfigureAwait(false);
        await ObserveAsync(
            AuthenticationEventTypes.SessionRevoked,
            session?.IdentityId,
            null,
            null,
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask DisableAsync(
        IdentityId identityId,
        CancellationToken cancellationToken = default)
    {
        var identity = await _identities.TryGetAsync(identityId, cancellationToken).ConfigureAwait(false);
        if (identity is null)
            return;

        identity.Disabled = true;
        await _identities.UpsertAsync(identity, cancellationToken).ConfigureAwait(false);
        var now = _time.GetUtcNow();
        await _sessions.RevokeAllForIdentityAsync(identityId, now, exceptSessionId: null, cancellationToken)
            .ConfigureAwait(false);
        await NotifyRevocationAsync(identityId, now, cancellationToken).ConfigureAwait(false);
        await ObserveAsync(
            AuthenticationEventTypes.IdentityDisabled,
            identityId,
            null,
            null,
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<SignInResult> ChangePasswordAsync(
        string identifier,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);
        ArgumentNullException.ThrowIfNull(currentPassword);
        ArgumentException.ThrowIfNullOrEmpty(newPassword);

        var identity = await _identities.FindByIdentifierAsync(identifier, cancellationToken)
            .ConfigureAwait(false);
        var credential = identity is null
            ? null
            : await _credentials.TryGetAsync(identity.CredentialReference, cancellationToken)
                .ConfigureAwait(false);
        var locked = credential is not null
            && await IsLockedAsync(credential, cancellationToken).ConfigureAwait(false);
        var hash = credential is null || locked ? _dummyHash : credential.PasswordHash;
        var currentMatches = _hasher.CompareHashedPassword(hash, currentPassword);
        if (identity is null || credential is null || identity.Disabled || locked || !currentMatches)
        {
            if (credential is not null && identity is not null && !identity.Disabled && !locked)
                await RecordFailureAsync(credential, identity.Id, cancellationToken).ConfigureAwait(false);

            await ObserveAsync(
                AuthenticationEventTypes.SignInFailed,
                identity?.Id,
                "identifier",
                "invalid_credentials",
                cancellationToken).ConfigureAwait(false);
            return SignInResult.Fail();
        }

        var policyError = await ValidateNewPasswordAsync(newPassword, identifier, cancellationToken)
            .ConfigureAwait(false);
        if (policyError is not null)
            return SignInResult.Fail(policyError);

        var now = _time.GetUtcNow();
        credential.PasswordHash = _hasher.HashPassword(newPassword);
        credential.UpdatedUtc = now;
        await _credentials.UpsertAsync(credential, cancellationToken).ConfigureAwait(false);
        await _sessions.RevokeAllForIdentityAsync(identity.Id, now, exceptSessionId: null, cancellationToken)
            .ConfigureAwait(false);
        await NotifyRevocationAsync(identity.Id, now, cancellationToken).ConfigureAwait(false);
        await ObserveAsync(
            AuthenticationEventTypes.PasswordChanged,
            identity.Id,
            "identifier",
            null,
            cancellationToken).ConfigureAwait(false);
        return SignInResult.Success(identity.Id);
    }

    /// <inheritdoc />
    public async ValueTask RevokeGrantsAsync(
        IdentityId identityId,
        CancellationToken cancellationToken = default)
    {
        var now = _time.GetUtcNow();
        await _sessions.RevokeAllForIdentityAsync(identityId, now, exceptSessionId: null, cancellationToken)
            .ConfigureAwait(false);
        await NotifyRevocationAsync(identityId, now, cancellationToken).ConfigureAwait(false);
        await ObserveAsync(
            AuthenticationEventTypes.GrantsRevoked,
            identityId,
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
        var now = _time.GetUtcNow();
        if (session is null || !session.IsActive(now))
            return null;

        if (_options.SessionIdleTimeout > TimeSpan.Zero)
        {
            var last = await _cache.GetAsync(IdleKey(sessionId), cancellationToken).ConfigureAwait(false);
            var lastUtc = last > 0
                ? DateTimeOffset.FromUnixTimeSeconds(last)
                : session.IssuedUtc;
            if (now - lastUtc > _options.SessionIdleTimeout)
                return null;

            var remaining = session.ExpiresUtc - now;
            if (remaining > TimeSpan.Zero)
            {
                await _cache.SetAsync(
                    IdleKey(sessionId),
                    now.ToUnixTimeSeconds(),
                    remaining,
                    cancellationToken).ConfigureAwait(false);
            }
        }

        var identity = await _identities.TryGetAsync(session.IdentityId, cancellationToken).ConfigureAwait(false);
        if (identity is { Disabled: true })
            return null;

        return session.IdentityId;
    }

    async ValueTask<string?> ValidateNewPasswordAsync(
        string password,
        string identifier,
        CancellationToken cancellationToken)
    {
        var minimum = Math.Max(_options.MinimumPasswordLength, AbsoluteMinimumPasswordLength);
        if (password.Length < minimum)
            return "password_too_short";

        if (ContainsForbiddenFragment(password, identifier))
            return "password_forbidden";

        if (_breachChecker is null)
        {
            if (!_options.IsDevelopment)
                throw new InvalidOperationException(
                    "IPasswordBreachChecker must be registered outside Development.");
            return null;
        }

        bool breached;
        try
        {
            breached = await _breachChecker.IsBreachedAsync(password, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception)
        {
            return "password_check_unavailable";
        }

        return breached ? "password_breached" : null;
    }

    bool ContainsForbiddenFragment(string password, string identifier)
    {
        if (password.Contains(identifier.Trim(), StringComparison.OrdinalIgnoreCase))
            return true;

        foreach (var fragment in _options.ForbiddenPasswordFragments)
        {
            if (!string.IsNullOrWhiteSpace(fragment)
                && password.Contains(fragment.Trim(), StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    async ValueTask<SignInResult> FinishSignInAsync(
        IdentityRecord identity,
        CredentialRecord credential,
        bool createSession,
        bool requireMfa,
        string? mfaProof,
        CancellationToken cancellationToken)
    {
        if (requireMfa)
        {
            var mfa = await _mfa.CompleteAsync(
                new MfaContext
                {
                    IdentityId = identity.Id,
                    Credential = credential.Reference,
                    Proof = mfaProof,
                },
                _cache,
                cancellationToken).ConfigureAwait(false);
            if (!mfa.Succeeded)
            {
                await RecordFailureAsync(credential, identity.Id, cancellationToken).ConfigureAwait(false);
                await ObserveAsync(
                    AuthenticationEventTypes.MfaFailed,
                    identity.Id,
                    "identifier",
                    mfa.Error ?? "mfa_invalid",
                    cancellationToken).ConfigureAwait(false);
                return SignInResult.Fail(mfa.Error ?? "mfa_invalid");
            }
        }

        await _cache.SetAsync(
            FailureKey(credential.Reference),
            0,
            _options.SignInFailureWindow,
            cancellationToken).ConfigureAwait(false);

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
            await _cache.SetAsync(
                IdleKey(session.SessionId),
                now.ToUnixTimeSeconds(),
                _options.SessionLifetime,
                cancellationToken).ConfigureAwait(false);
            await _sessions.RevokeAllForIdentityAsync(
                identity.Id,
                now,
                session.SessionId,
                cancellationToken).ConfigureAwait(false);

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

    async ValueTask<bool> IsLockedAsync(CredentialRecord credential, CancellationToken cancellationToken)
    {
        if (credential.Disabled)
            return true;
        return await _cache.GetAsync(LockKey(credential.Reference), cancellationToken).ConfigureAwait(false) > 0;
    }

    async ValueTask RecordFailureAsync(
        CredentialRecord credential,
        IdentityId identityId,
        CancellationToken cancellationToken)
    {
        var count = await _cache.IncrementAsync(
            FailureKey(credential.Reference),
            _options.SignInFailureWindow,
            cancellationToken).ConfigureAwait(false);
        if (count < _options.MaxSignInFailures)
            return;

        credential.Disabled = true;
        credential.UpdatedUtc = _time.GetUtcNow();
        await _credentials.UpsertAsync(credential, cancellationToken).ConfigureAwait(false);
        await _cache.SetAsync(
            LockKey(credential.Reference),
            1,
            _options.SignInFailureWindow,
            cancellationToken).ConfigureAwait(false);
        await ObserveAsync(
            AuthenticationEventTypes.CredentialLocked,
            identityId,
            "identifier",
            "credential_locked",
            cancellationToken).ConfigureAwait(false);
    }

    async ValueTask RecordUnknownFailureAsync(string identifier, CancellationToken cancellationToken)
    {
        await _cache.IncrementAsync(
            UnknownFailureKey(identifier),
            _options.SignInFailureWindow,
            cancellationToken).ConfigureAwait(false);
    }

    static string IdleKey(string sessionId) =>
        "auth:idle:" + sessionId;

    static string FailureKey(CredentialReference reference) =>
        "auth:fail:cred:" + reference;

    static string LockKey(CredentialReference reference) =>
        "auth:lock:cred:" + reference;

    static string UnknownFailureKey(string identifier)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(identifier.Trim()));
        return "auth:fail:id:" + Convert.ToHexString(hash);
    }

    async ValueTask NotifyRevocationAsync(
        IdentityId identityId,
        DateTimeOffset revokedUtc,
        CancellationToken cancellationToken)
    {
        foreach (var revocation in _revocations)
        {
            try
            {
                await revocation.RevokeAsync(identityId, revokedUtc, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // Revocation sinks must not roll back session state.
            }
        }
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
