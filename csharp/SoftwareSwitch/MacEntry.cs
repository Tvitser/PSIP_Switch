namespace SoftwareSwitch;

/// <summary>
/// Represents a single MAC address table entry that tracks which switch port a
/// host was last seen on and when, so that entries can expire automatically.
/// </summary>
public sealed class MacEntry
{
    public int Port { get; set; }
    public DateTime LastSeen { get; set; }

    public MacEntry(int port)
    {
        Port = port;
        LastSeen = DateTime.UtcNow;
    }

    /// <summary>Seconds elapsed since this entry was last refreshed.</summary>
    public double AgeSeconds() => (DateTime.UtcNow - LastSeen).TotalSeconds;

    /// <summary>Seconds of lifetime remaining given the configured TTL.</summary>
    public double LifetimeRemaining(int ttlSeconds) =>
        Math.Max(0.0, ttlSeconds - AgeSeconds());

    /// <summary>Returns true when the entry age equals or exceeds the TTL.</summary>
    public bool IsExpired(int ttlSeconds) => AgeSeconds() >= ttlSeconds;
}
