using System.Net.NetworkInformation;
using System.Text;

namespace SoftwareSwitch;

/// <summary>
/// Core two-port software switch logic.
/// <para>
/// Learns source MAC addresses, forwards frames to the correct output port,
/// tracks per-port protocol statistics, and expires stale MAC table entries
/// after <see cref="MacTtlSeconds"/> seconds of inactivity.
/// </para>
/// </summary>
public sealed class Switch : IDisposable
{
    public const int DefaultMacTtlSeconds = 300;
    private const int ExpiryCheckIntervalMs = 5_000;

    private readonly Dictionary<string, MacEntry> _macTable = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, PortStatistics> _stats = new()
    {
        [1] = new PortStatistics(),
        [2] = new PortStatistics(),
    };
    private readonly object _lock = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _expiryTask;

    public int MacTtlSeconds { get; private set; } = DefaultMacTtlSeconds;

    public IReadOnlyDictionary<int, PortStatistics> Stats => _stats;

    public Switch()
    {
        _expiryTask = Task.Run(ExpiryLoopAsync);
    }

    // -------------------------------------------------------------------------
    // MAC table
    // -------------------------------------------------------------------------

    /// <summary>Returns a snapshot of (mac, port, lifetime_remaining_s) sorted by MAC.</summary>
    public IReadOnlyList<(string Mac, int Port, double LifetimeRemaining)> MacTableSnapshot()
    {
        lock (_lock)
        {
            return _macTable
                .Select(kv => (kv.Key, kv.Value.Port, kv.Value.LifetimeRemaining(MacTtlSeconds)))
                .OrderBy(t => t.Key, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }

    public void ClearMacTable()
    {
        lock (_lock)
            _macTable.Clear();
    }

    public void SetMacTtl(int ttlSeconds)
    {
        if (ttlSeconds <= 0)
            throw new ArgumentOutOfRangeException(nameof(ttlSeconds), "MAC TTL must be a positive integer.");
        lock (_lock)
            MacTtlSeconds = ttlSeconds;
    }

    // -------------------------------------------------------------------------
    // Frame processing
    // -------------------------------------------------------------------------

    /// <summary>
    /// Process one Ethernet II frame arriving on <paramref name="inPort"/>.
    /// Updates MAC table and statistics, and returns which port to forward to.
    /// </summary>
    public ProcessFrameResult ProcessFrame(int inPort, byte[] frame)
    {
        if (inPort is not (1 or 2))
            throw new ArgumentException("inPort must be 1 or 2.", nameof(inPort));
        if (frame.Length < 14)
            throw new ArgumentException("Ethernet II frame must have at least 14 bytes.", nameof(frame));

        lock (_lock)
        {
            string dstMac = FormatMac(frame, 0);
            string srcMac = FormatMac(frame, 6);

            int outPort = _macTable.TryGetValue(dstMac, out var dstEntry) ? dstEntry.Port : 0;
            if (outPort == inPort || outPort is not (1 or 2))
                outPort = inPort == 1 ? 2 : 1;

            if (_macTable.TryGetValue(srcMac, out var existing))
            {
                existing.Port = inPort;
                existing.LastSeen = DateTime.UtcNow;
            }
            else
            {
                _macTable[srcMac] = new MacEntry(inPort);
            }

            var protocols = DetectProtocols(frame);
            _stats[inPort].IncrementRx(protocols);
            _stats[outPort].IncrementTx(protocols);

            return new ProcessFrameResult(inPort, outPort, srcMac, dstMac, protocols, frame);
        }
    }

    // -------------------------------------------------------------------------
    // Statistics
    // -------------------------------------------------------------------------

    public void ResetStatistics()
    {
        lock (_lock)
        {
            foreach (var s in _stats.Values)
                s.Reset();
        }
    }

    // -------------------------------------------------------------------------
    // Protocol detection
    // -------------------------------------------------------------------------

    private static IReadOnlyList<string> DetectProtocols(byte[] frame)
    {
        var found = new List<string> { "ethernet_ii" };
        if (frame.Length < 14)
            return found;

        ushort ethertype = (ushort)((frame[12] << 8) | frame[13]);
        if (ethertype == 0x0806)
        {
            found.Add("arp");
            return found;
        }

        if (ethertype != 0x0800 || frame.Length < 34)
            return found;

        found.Add("ip");
        int ipHeaderLen = (frame[14] & 0x0F) * 4;
        if (frame.Length < 14 + ipHeaderLen)
            return found;

        byte proto = frame[23];
        int l4Start = 14 + ipHeaderLen;

        if (proto == 1)
        {
            found.Add("icmp");
            return found;
        }

        if (proto == 6 && frame.Length >= l4Start + 20)
        {
            found.Add("tcp");
            int srcPort = (frame[l4Start] << 8) | frame[l4Start + 1];
            int dstPort = (frame[l4Start + 2] << 8) | frame[l4Start + 3];
            int dataOffset = (frame[l4Start + 12] >> 4) * 4;
            int payloadStart = l4Start + dataOffset;
            if ((srcPort == 80 || dstPort == 80) && frame.Length > payloadStart)
            {
                if (IsHttpPayload(frame, payloadStart))
                    found.Add("http");
            }

            return found;
        }

        if (proto == 17)
            found.Add("udp");

        return found;
    }

    private static bool IsHttpPayload(byte[] frame, int offset)
    {
        ReadOnlySpan<byte> payload = frame.AsSpan(offset);
        return payload.StartsWith("GET "u8)
            || payload.StartsWith("POST "u8)
            || payload.StartsWith("PUT "u8)
            || payload.StartsWith("DELETE "u8)
            || payload.StartsWith("HEAD "u8)
            || payload.StartsWith("HTTP/"u8);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static string FormatMac(byte[] frame, int offset)
    {
        var sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++)
        {
            if (i > 0) sb.Append(':');
            sb.Append(frame[offset + i].ToString("x2"));
        }
        return sb.ToString();
    }

    /// <summary>Returns all non-loopback network interface names.</summary>
    public static IReadOnlyList<string> AvailableInterfaces() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(ni => ni.Name)
            .OrderBy(n => n)
            .ToList();

    // -------------------------------------------------------------------------
    // MAC expiry background task
    // -------------------------------------------------------------------------

    private async Task ExpiryLoopAsync()
    {
        while (!_cts.Token.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(ExpiryCheckIntervalMs, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            PurgeExpiredEntries();
        }
    }

    public void PurgeExpiredEntries()
    {
        lock (_lock)
        {
            var expired = _macTable
                .Where(kv => kv.Value.IsExpired(MacTtlSeconds))
                .Select(kv => kv.Key)
                .ToList();
            foreach (var mac in expired)
                _macTable.Remove(mac);
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
    }
}
