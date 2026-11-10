namespace Novolis.Security.Authentication.Subjects;

/// <summary>Pepper settings for one-way secured login subjects (for example national ids).</summary>
public sealed class SecuredLoginOptions
{
    /// <summary>HMAC pepper. Required outside Development when development fallback is disabled.</summary>
    public string? Pepper { get; set; }

    /// <summary>Development-only fallback pepper.</summary>
    public string DevelopmentPepper { get; set; } =
        "novolis-development-secured-login-pepper-not-for-production";

    /// <summary>Whether an empty <see cref="Pepper"/> may fall back to <see cref="DevelopmentPepper"/>.</summary>
    public bool AllowDevelopmentPepper { get; set; }

    /// <summary>Purpose string bound into the HMAC.</summary>
    public string Purpose { get; set; } = "login/secured";
}
