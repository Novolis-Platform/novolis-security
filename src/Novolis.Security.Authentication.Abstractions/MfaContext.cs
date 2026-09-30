namespace Novolis.Security.Authentication;

/// <summary>Inputs for <see cref="IMfaProvider"/> after a correct password.</summary>
public sealed class MfaContext
{
    /// <summary>Identity that passed password verification.</summary>
    public IdentityId IdentityId { get; init; }

    /// <summary>Opaque credential locator. MFA must not treat this as a public identifier.</summary>
    public CredentialReference Credential { get; init; }

    /// <summary>Optional product proof (OTP, assertion, cached challenge response).</summary>
    public string? Proof { get; init; }
}
