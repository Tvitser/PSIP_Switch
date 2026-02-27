# PSIP_Switch

Minimal Python prototype for the 3rd lab:
- receives Ethernet II frames on port 1/2,
- forwards frames to the correct output port,
- keeps per-port RX/TX statistics (Ethernet II, ARP, IP, TCP, UDP, ICMP, HTTP).

## Run non-terminal GUI

```bash
python software_switch_gui.py
```

Then open:

`http://127.0.0.1:8080`

In the GUI, you can bind port `1` and `2` to real laptop interfaces and start physical bridge mode.
The process must run with raw-socket permissions (for example, `sudo python software_switch_gui.py` on Linux).

## Run tests

```bash
python -m unittest -v
```
