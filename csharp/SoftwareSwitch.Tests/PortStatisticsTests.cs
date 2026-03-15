using SoftwareSwitch;
using Xunit;

namespace SoftwareSwitch.Tests;

/// <summary>
/// Unit tests for <see cref="PortStatistics"/> – counter increment and reset.
/// </summary>
public class PortStatisticsTests
{
    [Fact]
    public void IncrementRx_CountsFrameAndProtocols()
    {
        var stats = new PortStatistics();
        stats.IncrementRx(["ethernet_ii", "ip", "tcp"]);

        Assert.Equal(1, stats.RxFrames);
        Assert.Equal(0, stats.TxFrames);
        Assert.Equal(1, stats.RxPdus["ethernet_ii"]);
        Assert.Equal(1, stats.RxPdus["ip"]);
        Assert.Equal(1, stats.RxPdus["tcp"]);
        Assert.Equal(0, stats.RxPdus["udp"]);
    }

    [Fact]
    public void IncrementTx_CountsFrameAndProtocols()
    {
        var stats = new PortStatistics();
        stats.IncrementTx(["ethernet_ii", "arp"]);

        Assert.Equal(0, stats.RxFrames);
        Assert.Equal(1, stats.TxFrames);
        Assert.Equal(1, stats.TxPdus["arp"]);
    }

    [Fact]
    public void Reset_ClearsAllCounters()
    {
        var stats = new PortStatistics();
        stats.IncrementRx(["ethernet_ii", "ip"]);
        stats.IncrementTx(["ethernet_ii"]);
        stats.Reset();

        Assert.Equal(0, stats.RxFrames);
        Assert.Equal(0, stats.TxFrames);
        foreach (var proto in PortStatistics.Protocols)
        {
            Assert.Equal(0, stats.RxPdus[proto]);
            Assert.Equal(0, stats.TxPdus[proto]);
        }
    }
}
