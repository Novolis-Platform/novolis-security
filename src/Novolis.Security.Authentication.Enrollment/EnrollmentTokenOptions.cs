namespace Novolis.Security.Authentication.Enrollment;

/// <summary>Host-supplied secrets and URL shape for enrollment links.</summary>
public sealed class EnrollmentTokenOptions
{
    /// <summary>HMAC pepper for token derivation. Required outside Development when no development pepper is allowed.</summary>
    public string? Pepper { get; set; }

    /// <summary>
    /// Fallback pepper used only when <see cref="AllowDevelopmentPepper"/> is true and <see cref="Pepper"/> is empty.
    /// </summary>
    public string DevelopmentPepper { get; set; } =
        "novolis-development-enrollment-pepper-not-for-production";

    /// <summary>Whether an empty <see cref="Pepper"/> may fall back to <see cref="DevelopmentPepper"/>.</summary>
    public bool AllowDevelopmentPepper { get; set; }

    /// <summary>Relative path segment after the public origin (no leading slash), default <c>invite</c>.</summary>
    public string LinkPath { get; set; } = "invite";

    /// <summary>Query parameter that carries the one-time token.</summary>
    public string TokenQueryName { get; set; } = "token";

    /// <summary>Purpose prefix for the recipient token HMAC.</summary>
    public string TokenPurpose { get; set; } = "enrollment/token";

    /// <summary>Purpose prefix for the durable token-hash HMAC.</summary>
    public string TokenHashPurpose { get; set; } = "enrollment/token-hash";

    /// <summary>Purpose prefix for the temporary credential HMAC.</summary>
    public string TemporaryPasswordPurpose { get; set; } = "enrollment/initial-password";

    /// <summary>Fixed prefix for derived temporary passwords (must satisfy host password policy).</summary>
    public string TemporaryPasswordPrefix { get; set; } = "En!9a";
}
