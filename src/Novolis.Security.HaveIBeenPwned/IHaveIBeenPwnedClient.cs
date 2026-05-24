namespace Novolis.Security.HaveIBeenPwned;

/// <summary>Have I Been Pwned password range API client.</summary>
public interface IHaveIBeenPwnedClient
{
    /// <summary>Returns true when the password hash appears in the breach corpus above <paramref name="threshold"/>.</summary>
    Task<bool> IsPwnedAsync(string password, uint threshold = 0);

    /// <summary>Returns breach details for a password hash range query.</summary>
    Task<IEnumerable<PasswordDetails>> GetPasswordDetailsAsync(string password);
}
