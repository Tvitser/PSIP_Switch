namespace SoftwareSwitch;

/// <summary>
/// Per-port frame and PDU counters for both RX (incoming) and TX (outgoing)
/// directions.  Protocols tracked: Ethernet II, ARP, IP, TCP, UDP, ICMP, HTTP.
/// </summary>
public sealed class PortStatistics
{
    public static readonly string[] Protocols =
        ["ethernet_ii", "arp", "ip", "tcp", "udp", "icmp", "http"];

    public long RxFrames { get; private set; }
    public long TxFrames { get; private set; }

    private readonly Dictionary<string, long> _rxPdus =
        Protocols.ToDictionary(p => p, _ => 0L);
    private readonly Dictionary<string, long> _txPdus =
        Protocols.ToDictionary(p => p, _ => 0L);

    public IReadOnlyDictionary<string, long> RxPdus => _rxPdus;
    public IReadOnlyDictionary<string, long> TxPdus => _txPdus;

    public void IncrementRx(IEnumerable<string> protocols)
    {
        RxFrames++;
        foreach (var p in protocols)
            if (_rxPdus.ContainsKey(p))
                _rxPdus[p]++;
    }

    public void IncrementTx(IEnumerable<string> protocols)
    {
        TxFrames++;
        foreach (var p in protocols)
            if (_txPdus.ContainsKey(p))
                _txPdus[p]++;
    }

    public void Reset()
    {
        RxFrames = 0;
        TxFrames = 0;
        foreach (var key in Protocols)
        {
            _rxPdus[key] = 0;
            _txPdus[key] = 0;
        }
    }
}
