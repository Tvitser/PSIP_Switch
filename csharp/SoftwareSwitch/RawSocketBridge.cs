using SharpPcap;

namespace SoftwareSwitch;

/// <summary>
/// Captures and sends raw Ethernet frames using SharpPcap (cross-platform, no P/Invoke).
/// Two network interfaces are bound as port 1 and port 2 of the switch and frames are
/// forwarded between them by <see cref="Switch"/>.
/// Requires libpcap (Linux/macOS) or Npcap (Windows) to be installed, and the process
/// to have the necessary permissions (CAP_NET_RAW on Linux, or run as root/Administrator).
/// </summary>
public sealed class RawSocketBridge : IDisposable
{
    private readonly Switch _switch;
    private ILiveDevice? _dev1;
    private ILiveDevice? _dev2;
    private string? _iface1;
    private string? _iface2;
    private volatile bool _running;

    // Stored so handlers can be unregistered in Stop() to avoid duplicate registrations
    // if Start() is called again after Stop().
    private PacketArrivalEventHandler? _handler1;
    private PacketArrivalEventHandler? _handler2;

    public bool IsRunning => _running;
    public string? Port1Interface => _iface1;
    public string? Port2Interface => _iface2;

    public RawSocketBridge(Switch sw)
    {
        _switch = sw;
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// <summary>Opens pcap devices and starts capture on both interfaces.</summary>
    public void Start(string iface1, string iface2)
    {
        if (_running)
            throw new InvalidOperationException("Bridge is already running.");
        if (string.IsNullOrWhiteSpace(iface1) || string.IsNullOrWhiteSpace(iface2))
            throw new ArgumentException("Both interfaces are required.");
        if (string.Equals(iface1, iface2, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Interfaces for port 1 and port 2 must be different.");

        _dev1 = OpenDevice(iface1);
        try
        {
            _dev2 = OpenDevice(iface2);
        }
        catch
        {
            _dev1.Close();
            _dev1 = null;
            throw;
        }

        _iface1 = iface1;
        _iface2 = iface2;
        _running = true;

        _handler1 = (_, e) => OnPacket(e, inPort: 1);
        _handler2 = (_, e) => OnPacket(e, inPort: 2);
        _dev1.OnPacketArrival += _handler1;
        _dev2.OnPacketArrival += _handler2;

        _dev1.StartCapture();
        _dev2.StartCapture();
    }

    /// <summary>Stops capture and closes the pcap devices.</summary>
    public void Stop()
    {
        _running = false;
        CloseDevice(ref _dev1, _handler1);
        CloseDevice(ref _dev2, _handler2);
        _handler1 = null;
        _handler2 = null;
        _iface1 = null;
        _iface2 = null;
    }

    private static void CloseDevice(ref ILiveDevice? dev, PacketArrivalEventHandler? handler)
    {
        if (dev == null) return;
        if (handler != null)
            dev.OnPacketArrival -= handler;
        try { dev.StopCapture(); } catch { }
        dev.Close();
        dev = null;
    }

    // -------------------------------------------------------------------------
    // Packet handler
    // -------------------------------------------------------------------------

    // Switch.ProcessFrame is internally synchronized with a lock, so concurrent
    // invocations from the two device capture threads are safe.
    private void OnPacket(PacketCapture e, int inPort)
    {
        if (!_running) return;

        // Copy from the ref struct's ReadOnlySpan<byte> into an array for Switch.ProcessFrame.
        byte[] frame = e.Data.ToArray();
        if (frame.Length < 14) return;

        try
        {
            var result = _switch.ProcessFrame(inPort, frame);
            var outDev = result.OutPort == 1 ? _dev1 : _dev2;
            outDev?.SendPacket(result.Frame);
        }
        catch (ArgumentException)
        {
            // Frame too short or malformed; discard.
        }
    }

    // -------------------------------------------------------------------------
    // Device helpers
    // -------------------------------------------------------------------------

    private static ILiveDevice OpenDevice(string name)
    {
        CaptureDeviceList devices;
        try
        {
            devices = CaptureDeviceList.New();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "Cannot enumerate capture devices. Ensure libpcap/Npcap is installed and " +
                "the process has the required permissions (CAP_NET_RAW or root).", ex);
        }

        var dev = devices.FirstOrDefault(d =>
            string.Equals(d.Name, name, StringComparison.OrdinalIgnoreCase));

        if (dev == null)
            throw new InvalidOperationException(
                $"Interface '{name}' not found. " +
                $"Available: {string.Join(", ", devices.Select(d => d.Name))}");

        // Use a ConfigurationFailed handler so that options unsupported on the current
        // platform (e.g. NoCaptureLocal on some Linux libpcap versions) are skipped
        // instead of throwing.
        var config = new DeviceConfiguration
        {
            Mode = DeviceModes.Promiscuous | DeviceModes.NoCaptureLocal,
            ReadTimeout = 250,
        };
        config.ConfigurationFailed += static (_, _) => { /* ignore unsupported options */ };

        dev.Open(config);
        return dev;
    }

    /// <summary>Returns all pcap-visible device names, or an empty list if libpcap is unavailable.</summary>
    public static IReadOnlyList<string> AvailableDeviceNames()
    {
        try
        {
            return CaptureDeviceList.New()
                .Select(d => d.Name)
                .OrderBy(n => n)
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    public void Dispose() => Stop();
}
