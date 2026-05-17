namespace Novolis.Security.HaveIBeenPwned;

public interface IHaveIBeenPwnedClient
{
    Task<bool> IsPwnedAsync(string password, uint threshold = 0);
    Task<IEnumerable<PasswordDetails>> GetPasswordDetailsAsync(string password);
}