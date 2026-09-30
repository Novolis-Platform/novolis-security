namespace Novolis.Security.Authentication;

/// <summary>Structured authentication observation without raw credentials or secrets.</summary>
public sealed class AuthenticationSecurityEvent
{
    /// <summary>Event timestamp from the configured authentication clock.</summary>
    public DateTimeOffset Utc { get; init; }

    /// <summary>Stable event type.</summary>
    public string Type { get; init; } = "";

    /// <summary>Global identity when known.</summary>
    public IdentityId? IdentityId { get; init; }

    /// <summary>Identifier category, never the raw secret.</summary>
    public string? IdentifierType { get; init; }

    /// <summary>Failure code when an operation was denied.</summary>
    public string? Error { get; init; }
}
