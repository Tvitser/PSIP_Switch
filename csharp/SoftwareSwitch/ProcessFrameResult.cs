namespace SoftwareSwitch;

/// <summary>
/// Result of processing a single Ethernet frame through the switch.
/// </summary>
public sealed record ProcessFrameResult(
    int InPort,
    int OutPort,
    string SrcMac,
    string DstMac,
    IReadOnlyList<string> Protocols,
    byte[] Frame);
