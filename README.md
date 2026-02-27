# PSIP_Switch

Minimal Python prototype for the 3rd lab:
- receives Ethernet II frames on port 1/2,
- forwards frames to the correct output port,
- keeps per-port RX/TX statistics (Ethernet II, ARP, IP, TCP, UDP, ICMP, HTTP).

## Run non-terminal GUI

```bash
python /home/runner/work/PSIP_Switch/PSIP_Switch/software_switch_gui.py
```

Then open:

`http://127.0.0.1:8080`

## Run tests

```bash
python -m unittest -v
```
