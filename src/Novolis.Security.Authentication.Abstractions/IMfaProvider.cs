namespace Novolis.Security.Authentication;

/// <summary>
/// Product-supplied second factor after a correct password.
/// The library default is <see cref="NoopMfaProvider"/>; Authentication does not implement TOTP, WebAuthn, or SMS.
/// </summary>
public interface IMfaProvider
{
    /// <summary>
    /// Completes the second factor. Use <paramref name="cache"/> for short-lived challenges and one-time proofs
    /// so every process sees the same MFA state.
    /// </summary>
    ValueTask<MfaDecision> CompleteAsync(
        MfaContext context,
        ICacheStore cache,
        CancellationToken cancellationToken = default);
}
