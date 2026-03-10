# PSIP_Switch

A two-port software switch prototype available in both **Python** and **C#**.

Both implementations:
- receive Ethernet II frames on port 1/2,
- learn source MAC addresses and forward frames to the correct output port,
- expire stale MAC table entries (configurable TTL, default 300 s),
- keep per-port RX/TX statistics (Ethernet II, ARP, IP, TCP, UDP, ICMP, HTTP).

---

## Python prototype

### Run web GUI

```bash
python software_switch_gui.py
```

Then open `http://127.0.0.1:8080`

Raw-socket bridge mode requires `CAP_NET_RAW` / root:

```bash
sudo python software_switch_gui.py
```

### GUI features

| Section | Controls |
|---------|----------|
| Physical bridge | Start / Stop bridge on two real interfaces |
| Process Frame | Submit a hex-encoded Ethernet frame to test forwarding |
| MAC table | Displays MAC address · port · **lifetime remaining (s)**; **Set TTL** and **Clear MAC table** buttons |
| Protocol statistics | RX/TX counters per port per protocol; **Reset statistics** button |

### Run tests

```bash
python -m unittest -v
```

---

## C# prototype

### Build

```bash
dotnet build csharp/SoftwareSwitch/SoftwareSwitch.csproj
```

### Run web GUI

```bash
dotnet run --project csharp/SoftwareSwitch
```

Then open `http://127.0.0.1:8080`

Raw-socket bridge mode uses Linux `AF_PACKET` sockets and requires root / `CAP_NET_RAW`.

Optional arguments: `[host] [port]`

```bash
sudo dotnet run --project csharp/SoftwareSwitch -- 0.0.0.0 8080
```

### Run tests

```bash
dotnet test csharp/SoftwareSwitch.Tests
```
