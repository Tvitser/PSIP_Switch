using SoftwareSwitch;
using Xunit;

namespace SoftwareSwitch.Tests;

/// <summary>
/// Unit tests for <see cref="MacEntry"/> – TTL / lifetime calculations.
/// </summary>
public class MacEntryTests
{
    [Fact]
    public void NewEntry_IsNotExpired()
    {
        var entry = new MacEntry(port: 1);
        Assert.False(entry.IsExpired(300));
    }

    [Fact]
    public void StaleEntry_IsExpired()
    {
        var entry = new MacEntry(port: 1)
        {
            LastSeen = DateTime.UtcNow.AddSeconds(-9999),
        };
        Assert.True(entry.IsExpired(300));
    }

    [Fact]
    public void LifetimeRemaining_DecreasesWithAge()
    {
        var entry = new MacEntry(port: 1)
        {
            LastSeen = DateTime.UtcNow.AddSeconds(-10),
        };
        double remaining = entry.LifetimeRemaining(300);
        Assert.InRange(remaining, 285, 295); // allow ±5 s timing slack
    }

    [Fact]
    public void LifetimeRemaining_NeverNegative()
    {
        var entry = new MacEntry(port: 1)
        {
            LastSeen = DateTime.UtcNow.AddSeconds(-99999),
        };
        Assert.Equal(0.0, entry.LifetimeRemaining(300));
    }
}
