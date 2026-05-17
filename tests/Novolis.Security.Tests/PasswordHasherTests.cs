using System.Diagnostics;
using Novolis.Security.PasswordHashing;
using Microsoft.Extensions.Options;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class PasswordHasherTests
{
    [Test]
    [Arguments("password", 128)]
    [Arguments("password", 256)]
    [Arguments("password", 512)]
    [Arguments("password", 1024)]
    public async Task HashPassword(string password, int iterations)
    {
        var options = Options.Create(new PasswordHasherOptions { Iterations = iterations });
        var hasher = new PasswordHasher(options);

        var stopwatch = Stopwatch.StartNew();
        var hash = hasher.HashPassword(password);
        stopwatch.Stop();
        TestContext.Current?.OutputWriter.WriteLine(hash);

        var result = hasher.CompareHashedPassword(hash, password);

        await Assert.That(hash).IsNotNullOrEmpty();
        await Assert.That(result).IsTrue();
        TestContext.Current?.OutputWriter.WriteLine($"Hashing took {stopwatch.ElapsedMilliseconds} ms for {iterations} iterations.");
    }
}
