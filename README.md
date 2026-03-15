# PSIP_Switch

A two-port software Ethernet switch implemented in **C#**.

The switch:
- captures raw Ethernet frames on two network interfaces via **SharpPcap 6.3.1**,
- learns source MAC addresses and forwards frames to the correct output port,
- expires stale MAC table entries (configurable TTL, default 300 s),
- tracks per-port RX/TX statistics (Ethernet II, ARP, IP, TCP, UDP, ICMP, HTTP).

---

## Build

```bash
dotnet build csharp/SoftwareSwitch/SoftwareSwitch.csproj
```

## Run web GUI

```bash
dotnet run --project csharp/SoftwareSwitch
```

Then open `http://127.0.0.1:8080`

Raw-socket bridge mode requires **libpcap** (Linux/macOS) or **Npcap** (Windows)
and `CAP_NET_RAW` / root / Administrator:

```bash
sudo dotnet run --project csharp/SoftwareSwitch
```

Optional arguments: `[host] [port]`

```bash
sudo dotnet run --project csharp/SoftwareSwitch -- 0.0.0.0 8080
```

**Prerequisite:** `sudo apt install libpcap-dev` (Debian/Ubuntu) or install [Npcap](https://npcap.com/) on Windows.

### GUI features

| Section | Controls |
|---------|----------|
| Physical bridge | Start / Stop bridge on two real interfaces |
| Process Frame | Submit a hex-encoded Ethernet frame to test forwarding |
| MAC table | Displays MAC address · port · **lifetime remaining (s)**; **Set TTL** and **Clear MAC table** buttons |
| Protocol statistics | RX/TX counters per port per protocol; **Reset statistics** button |

## Run tests

```bash
dotnet test csharp/SoftwareSwitch.Tests
```

## Documentation

LaTeX source: [`docs/documentation.tex`](docs/documentation.tex)

Compile with:
```bash
cd docs && pdflatex documentation.tex && pdflatex documentation.tex
```
