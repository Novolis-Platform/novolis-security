namespace Novolis.Security.OAuth.Client;

/// <summary>Computes cache lifetime from <c>expires_in</c>.</summary>
internal static class NovolisOAuthTokenLifetime
{
    internal const int SkewSeconds = 60;
    internal const int FallbackSeconds = 300;

    /// <summary>Returns the usable lifetime after subtracting refresh skew.</summary>
    public static TimeSpan FromExpiresIn(int? expiresIn)
    {
        if (expiresIn is null)
        {
            return TimeSpan.FromSeconds(FallbackSeconds);
        }

        return TimeSpan.FromSeconds(Math.Max(1, expiresIn.Value - SkewSeconds));
    }
}
