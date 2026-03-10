using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace SoftwareSwitch;

/// <summary>
/// Captures and sends raw Ethernet frames on Linux using AF_PACKET sockets
/// via P/Invoke.  Two network interfaces are bound as port 1 and port 2 of
/// the switch and frames are forwarded between them by <see cref="Switch"/>.
/// </summary>
public sealed class RawSocketBridge : IDisposable
{
    // AF_PACKET = 17, SOCK_RAW = 3, ETH_P_ALL = 0x0003 (network byte order = 0x0300)
    private const int AfPacket = 17;
    private const int SockRaw = 3;
    private const int EthPAll = 0x0003;
    // pkttype == PACKET_OUTGOING (4) means the kernel is telling us about a frame
    // that we sent; skip it to prevent forwarding loops.
    private const byte PacketOutgoing = 4;

    [DllImport("libc", SetLastError = true, EntryPoint = "socket")]
    private static extern int NativeSocket(int domain, int type, int protocol);

    [DllImport("libc", SetLastError = true, EntryPoint = "bind")]
    private static extern int NativeBind(int sockfd, ref SockAddrLl addr, int addrlen);

    [DllImport("libc", SetLastError = true, EntryPoint = "recvfrom")]
    private static extern int NativeRecvFrom(int sockfd, byte[] buf, int len, int flags,
        ref SockAddrLl src_addr, ref int addrlen);

    [DllImport("libc", SetLastError = true, EntryPoint = "send")]
    private static extern int NativeSend(int sockfd, byte[] buf, int len, int flags);

    [DllImport("libc", SetLastError = true, EntryPoint = "close")]
    private static extern int NativeClose(int fd);

    [DllImport("libc", SetLastError = true, EntryPoint = "if_nametoindex")]
    private static extern uint NativeIfNameToIndex([MarshalAs(UnmanagedType.LPStr)] string ifname);

    // sockaddr_ll – Linux low-level socket address for AF_PACKET
    [StructLayout(LayoutKind.Sequential)]
    private struct SockAddrLl
    {
        public ushort SllFamily;
        public ushort SllProtocol;
        public int SllIfindex;
        public ushort SllHatype;
        public byte SllPkttype;
        public byte SllHalen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] SllAddr;
    }

    private readonly Switch _switch;
    private int _fd1 = -1;
    private int _fd2 = -1;
    private string? _iface1;
    private string? _iface2;
    private Thread? _thread;
    private volatile bool _running;

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

    /// <summary>Opens AF_PACKET sockets and starts the capture thread.</summary>
    public void Start(string iface1, string iface2)
    {
        if (_running)
            throw new InvalidOperationException("Bridge is already running.");
        if (string.IsNullOrWhiteSpace(iface1) || string.IsNullOrWhiteSpace(iface2))
            throw new ArgumentException("Both interfaces are required.");
        if (string.Equals(iface1, iface2, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Interfaces for port 1 and port 2 must be different.");

        _fd1 = OpenSocket(iface1);
        try
        {
            _fd2 = OpenSocket(iface2);
        }
        catch
        {
            NativeClose(_fd1);
            _fd1 = -1;
            throw;
        }

        _iface1 = iface1;
        _iface2 = iface2;
        _running = true;
        _thread = new Thread(CaptureLoop) { IsBackground = true, Name = "BridgeCaptureLoop" };
        _thread.Start();
    }

    /// <summary>Stops the capture thread and closes sockets.</summary>
    public void Stop()
    {
        _running = false;
        if (_fd1 != -1) { NativeClose(_fd1); _fd1 = -1; }
        if (_fd2 != -1) { NativeClose(_fd2); _fd2 = -1; }
        _thread?.Join(TimeSpan.FromSeconds(2));
        _thread = null;
        _iface1 = null;
        _iface2 = null;
    }

    // -------------------------------------------------------------------------
    // Internal capture loop
    // -------------------------------------------------------------------------

    private void CaptureLoop()
    {
        byte[] buf = new byte[65535];
        var srcAddr = new SockAddrLl { SllAddr = new byte[8] };

        while (_running)
        {
            // Poll port 1
            TryReceive(_fd1, 1, buf, ref srcAddr);
            // Poll port 2
            TryReceive(_fd2, 2, buf, ref srcAddr);
        }
    }

    private void TryReceive(int fd, int inPort, byte[] buf, ref SockAddrLl srcAddr)
    {
        if (fd < 0) return;

        int addrLen = Marshal.SizeOf<SockAddrLl>();
        srcAddr.SllAddr ??= new byte[8];
        int n = NativeRecvFrom(fd, buf, buf.Length, 0, ref srcAddr, ref addrLen);
        if (n <= 0) return;

        // Skip frames the kernel reports as PACKET_OUTGOING to prevent loops
        if (srcAddr.SllPkttype == PacketOutgoing) return;

        byte[] frame = buf[..n];
        try
        {
            var result = _switch.ProcessFrame(inPort, frame);
            int outFd = result.OutPort == 1 ? _fd1 : _fd2;
            if (outFd >= 0)
                NativeSend(outFd, result.Frame, result.Frame.Length, 0);
        }
        catch (ArgumentException)
        {
            // Frame too short or invalid; discard
        }
    }

    // -------------------------------------------------------------------------
    // Socket helpers
    // -------------------------------------------------------------------------

    private static int OpenSocket(string iface)
    {
        // htons(ETH_P_ALL) = 0x0300
        int fd = NativeSocket(AfPacket, SockRaw, (int)System.Net.IPAddress.HostToNetworkOrder((short)EthPAll) & 0xFFFF);
        if (fd < 0)
        {
            int err = Marshal.GetLastSystemError();
            throw new InvalidOperationException(
                $"socket(AF_PACKET, SOCK_RAW, ETH_P_ALL) failed with errno {err}. " +
                "Ensure the process has CAP_NET_RAW or is run as root.");
        }

        uint ifindex = NativeIfNameToIndex(iface);
        if (ifindex == 0)
        {
            NativeClose(fd);
            throw new InvalidOperationException($"Interface '{iface}' not found.");
        }

        var addr = new SockAddrLl
        {
            SllFamily = AfPacket,
            SllProtocol = (ushort)((int)System.Net.IPAddress.HostToNetworkOrder((short)EthPAll) & 0xFFFF),
            SllIfindex = (int)ifindex,
            SllAddr = new byte[8],
        };

        if (NativeBind(fd, ref addr, Marshal.SizeOf<SockAddrLl>()) < 0)
        {
            int err = Marshal.GetLastSystemError();
            NativeClose(fd);
            throw new InvalidOperationException($"bind() on '{iface}' failed with errno {err}.");
        }

        return fd;
    }

    public void Dispose() => Stop();
}
