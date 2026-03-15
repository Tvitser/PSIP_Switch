using SoftwareSwitch;
using Xunit;

namespace SoftwareSwitch.Tests;

/// <summary>
/// Unit tests for <see cref="Switch"/> – frame processing, MAC learning,
/// statistics, MAC table TTL, and clear/set operations.
/// </summary>
public class SwitchTests : IDisposable
{
    private readonly Switch _sw = new();

    public void Dispose() => _sw.Dispose();

    // -------------------------------------------------------------------------
    // Helper: build test frames
    // -------------------------------------------------------------------------

    /// <summary>Minimal Ethernet II / IP / TCP frame with HTTP GET payload.</summary>
    private static byte[] TcpHttpFrame()
    {
        byte[] dst = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        byte[] src = [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB];
        byte[] ethertype = [0x08, 0x00];

        // IPv4 header: IHL=5, proto=TCP(6), src=192.168.0.2, dst=192.168.0.1
        byte[] ip =
        [
            0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06,
            0x00, 0x00, 192, 168, 0, 2, 192, 168, 0, 1,
        ];

        // TCP header: src=12345 dst=80 (HTTP), data offset=5 (20 bytes)
        byte[] tcp = Convert.FromHexString("3039005000000000000000005018000000000000");
        byte[] payload = System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n");

        return [.. dst, .. src, .. ethertype, .. ip, .. tcp, .. payload];
    }

    /// <summary>Minimal Ethernet II / ARP frame.</summary>
    private static byte[] ArpFrame(byte[] dst, byte[] src)
    {
        byte[] ethertype = [0x08, 0x06];
        byte[] arpPayload = new byte[28];
        return [.. dst, .. src, .. ethertype, .. arpPayload];
    }

    // -------------------------------------------------------------------------
    // Frame forwarding
    // -------------------------------------------------------------------------

    [Fact]
    public void ProcessFrame_ForwardsToOppositePort_WhenDstUnknown()
    {
        var result = _sw.ProcessFrame(1, TcpHttpFrame());
        Assert.Equal(2, result.OutPort);
    }

    [Fact]
    public void ProcessFrame_ForwardsToLearnedPort()
    {
        // Teach the switch that 66:77:88:99:aa:bb is on port 1
        _sw.ProcessFrame(1, TcpHttpFrame());

        // Now send a frame addressed TO that MAC from port 2
        byte[] dst = [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB];
        byte[] src = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        var frame2 = ArpFrame(dst, src);
        var result = _sw.ProcessFrame(2, frame2);

        Assert.Equal(1, result.OutPort);
    }

    [Fact]
    public void ProcessFrame_RejectsInvalidPort()
    {
        var ex = Assert.Throws<ArgumentException>(() => _sw.ProcessFrame(3, TcpHttpFrame()));
        Assert.Contains("inPort", ex.Message);
    }

    [Fact]
    public void ProcessFrame_RejectsTooShortFrame()
    {
        var ex = Assert.Throws<ArgumentException>(() => _sw.ProcessFrame(1, new byte[10]));
        Assert.Contains("14 bytes", ex.Message);
    }

    // -------------------------------------------------------------------------
    // Protocol detection
    // -------------------------------------------------------------------------

    [Fact]
    public void ProcessFrame_DetectsHttpTcpIpEthernetII()
    {
        var result = _sw.ProcessFrame(1, TcpHttpFrame());
        Assert.Contains("ethernet_ii", result.Protocols);
        Assert.Contains("ip", result.Protocols);
        Assert.Contains("tcp", result.Protocols);
        Assert.Contains("http", result.Protocols);
    }

    [Fact]
    public void ProcessFrame_DetectsArp()
    {
        byte[] dst = new byte[6];
        byte[] src = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        var result = _sw.ProcessFrame(1, ArpFrame(dst, src));
        Assert.Contains("arp", result.Protocols);
        Assert.DoesNotContain("ip", result.Protocols);
    }

    [Fact]
    public void ProcessFrame_DetectsIcmp()
    {
        // Build Ethernet + IP(proto=1/ICMP)
        byte[] dst = new byte[6];
        byte[] src = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        byte[] ethertype = [0x08, 0x00];
        byte[] ip =
        [
            0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x40,
            0x01, // proto = ICMP
            0x00, 0x00, 192, 168, 0, 1, 192, 168, 0, 2,
        ];
        byte[] icmpPayload = new byte[8];
        byte[] frame = [.. dst, .. src, .. ethertype, .. ip, .. icmpPayload];

        var result = _sw.ProcessFrame(1, frame);
        Assert.Contains("icmp", result.Protocols);
    }

    [Fact]
    public void ProcessFrame_DetectsUdp()
    {
        byte[] dst = new byte[6];
        byte[] src = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        byte[] ethertype = [0x08, 0x00];
        byte[] ip =
        [
            0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x40,
            0x11, // proto = UDP
            0x00, 0x00, 192, 168, 0, 1, 192, 168, 0, 2,
        ];
        byte[] udpHeader = [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];
        byte[] frame = [.. dst, .. src, .. ethertype, .. ip, .. udpHeader];

        var result = _sw.ProcessFrame(1, frame);
        Assert.Contains("udp", result.Protocols);
    }

    // -------------------------------------------------------------------------
    // Statistics
    // -------------------------------------------------------------------------

    [Fact]
    public void Statistics_IncrementsRxOnInPort_TxOnOutPort()
    {
        _sw.ProcessFrame(1, TcpHttpFrame());

        Assert.Equal(1, _sw.Stats[1].RxFrames);
        Assert.Equal(0, _sw.Stats[1].TxFrames);
        Assert.Equal(0, _sw.Stats[2].RxFrames);
        Assert.Equal(1, _sw.Stats[2].TxFrames);
        Assert.Equal(1, _sw.Stats[1].RxPdus["http"]);
        Assert.Equal(1, _sw.Stats[2].TxPdus["http"]);
    }

    [Fact]
    public void ResetStatistics_ClearsAllCounters()
    {
        _sw.ProcessFrame(1, TcpHttpFrame());
        _sw.ResetStatistics();

        foreach (var portNum in new[] { 1, 2 })
        {
            var s = _sw.Stats[portNum];
            Assert.Equal(0, s.RxFrames);
            Assert.Equal(0, s.TxFrames);
            foreach (var proto in PortStatistics.Protocols)
            {
                Assert.Equal(0, s.RxPdus[proto]);
                Assert.Equal(0, s.TxPdus[proto]);
            }
        }
    }

    // -------------------------------------------------------------------------
    // MAC table
    // -------------------------------------------------------------------------

    [Fact]
    public void MacTableSnapshot_ContainsLearnedEntry()
    {
        _sw.ProcessFrame(1, TcpHttpFrame());
        var snap = _sw.MacTableSnapshot();

        Assert.NotEmpty(snap);
        var (_, port, lifetime) = snap[0];
        Assert.Equal(1, port);
        Assert.True(lifetime > 0);
        Assert.True(lifetime <= Switch.DefaultMacTtlSeconds);
    }

    [Fact]
    public void ClearMacTable_RemovesAllEntries()
    {
        _sw.ProcessFrame(1, TcpHttpFrame());
        Assert.NotEmpty(_sw.MacTableSnapshot());

        _sw.ClearMacTable();
        Assert.Empty(_sw.MacTableSnapshot());
    }

    [Fact]
    public void SetMacTtl_UpdatesValue()
    {
        _sw.SetMacTtl(60);
        Assert.Equal(60, _sw.MacTtlSeconds);
    }

    [Fact]
    public void SetMacTtl_RejectsNonPositive()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _sw.SetMacTtl(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => _sw.SetMacTtl(-1));
    }

    [Fact]
    public void PurgeExpiredEntries_RemovesStaleMacs()
    {
        _sw.ProcessFrame(1, TcpHttpFrame());
        _sw.SetMacTtl(1);
        System.Threading.Thread.Sleep(1100);
        _sw.PurgeExpiredEntries();

        Assert.Empty(_sw.MacTableSnapshot());
    }

    [Fact]
    public void MacEntry_RefreshedOnSecondFrame_SameMac()
    {
        byte[] frame = TcpHttpFrame();
        _sw.ProcessFrame(1, frame);
        var snap1 = _sw.MacTableSnapshot();

        System.Threading.Thread.Sleep(50);
        _sw.ProcessFrame(1, frame);
        var snap2 = _sw.MacTableSnapshot();

        Assert.Single(snap2);
        // The second snapshot should have a slightly shorter age, i.e., same or higher lifetime
        Assert.True(snap2[0].LifetimeRemaining >= snap1[0].LifetimeRemaining - 1);
    }
}
