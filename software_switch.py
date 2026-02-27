from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


PROTOCOLS = ("ethernet_ii", "arp", "ip", "tcp", "udp", "icmp", "http")


@dataclass
class PortStatistics:
    rx_frames: int = 0
    tx_frames: int = 0
    rx_pdus: Dict[str, int] = field(default_factory=lambda: {p: 0 for p in PROTOCOLS})
    tx_pdus: Dict[str, int] = field(default_factory=lambda: {p: 0 for p in PROTOCOLS})

    def reset(self) -> None:
        self.rx_frames = 0
        self.tx_frames = 0
        for protocol in PROTOCOLS:
            self.rx_pdus[protocol] = 0
            self.tx_pdus[protocol] = 0


class SoftwareSwitch:
    """Minimal two-port software switch prototype for lab 3.

    It accepts Ethernet II frames, learns source MAC addresses, and forwards
    frames to the opposite port (or to the learned destination port).
    """

    def __init__(self) -> None:
        self.stats = {1: PortStatistics(), 2: PortStatistics()}
        self.mac_table: Dict[str, int] = {}

    @staticmethod
    def _mac(raw: bytes) -> str:
        return ":".join(f"{b:02x}" for b in raw)

    @staticmethod
    def _is_http_payload(payload: bytes) -> bool:
        prefixes = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"HTTP/")
        return payload.startswith(prefixes)

    def _detect_protocols(self, frame: bytes) -> set[str]:
        found = {"ethernet_ii"}
        if len(frame) < 14:
            return found

        ethertype = int.from_bytes(frame[12:14], "big")
        if ethertype == 0x0806:
            found.add("arp")
            return found
        if ethertype != 0x0800 or len(frame) < 34:
            return found

        found.add("ip")
        ip_header_len = (frame[14] & 0x0F) * 4
        if len(frame) < 14 + ip_header_len:
            return found

        proto = frame[23]
        l4_start = 14 + ip_header_len

        if proto == 1:
            found.add("icmp")
            return found

        if proto == 6 and len(frame) >= l4_start + 20:
            found.add("tcp")
            src_port = int.from_bytes(frame[l4_start : l4_start + 2], "big")
            dst_port = int.from_bytes(frame[l4_start + 2 : l4_start + 4], "big")
            data_offset = (frame[l4_start + 12] >> 4) * 4
            payload_start = l4_start + data_offset
            if 80 in (src_port, dst_port) and len(frame) > payload_start:
                if self._is_http_payload(frame[payload_start:]):
                    found.add("http")
            return found

        if proto == 17:
            found.add("udp")

        return found

    def process_frame(self, in_port: int, frame: bytes) -> dict:
        if in_port not in (1, 2):
            raise ValueError("in_port must be 1 or 2")
        if len(frame) < 14:
            raise ValueError("Ethernet II frame must have at least 14 bytes")

        dst_mac = self._mac(frame[0:6])
        src_mac = self._mac(frame[6:12])
        out_port = self.mac_table.get(dst_mac)
        if out_port == in_port:
            out_port = 2 if in_port == 1 else 1
        if out_port not in (1, 2):
            out_port = 2 if in_port == 1 else 1

        self.mac_table[src_mac] = in_port

        protocols = self._detect_protocols(frame)
        in_stats = self.stats[in_port]
        out_stats = self.stats[out_port]

        in_stats.rx_frames += 1
        out_stats.tx_frames += 1
        for protocol in protocols:
            in_stats.rx_pdus[protocol] += 1
            out_stats.tx_pdus[protocol] += 1

        return {
            "in_port": in_port,
            "out_port": out_port,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "protocols": sorted(protocols),
            "frame": frame,
        }

    def reset_statistics(self) -> None:
        for port in self.stats.values():
            port.reset()
