from __future__ import annotations

from dataclasses import dataclass, field
from select import select
import socket
from threading import Event, Lock, Thread
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
        self._lock = Lock()
        self._bridge_stop = Event()
        self._bridge_thread: Thread | None = None
        self._bridge_sockets: Dict[int, socket.socket] = {}
        self._bridge_ifaces: Dict[int, str] = {}

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
        with self._lock:
            if in_port not in (1, 2):
                raise ValueError("in_port must be 1 or 2")
            if len(frame) < 14:
                raise ValueError("Ethernet II frame must have at least 14 bytes")

            dst_mac = self._mac(frame[0:6])
            src_mac = self._mac(frame[6:12])
            out_port = self.mac_table.get(dst_mac)
            if out_port == in_port or out_port not in (1, 2):
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
        with self._lock:
            for port in self.stats.values():
                port.reset()

    @staticmethod
    def available_interfaces() -> list[str]:
        return sorted(name for _, name in socket.if_nameindex() if name != "lo")

    @property
    def bridge_running(self) -> bool:
        return self._bridge_thread is not None and self._bridge_thread.is_alive()

    @property
    def bridge_interfaces(self) -> Dict[int, str]:
        return dict(self._bridge_ifaces)

    @staticmethod
    def _open_bridge_socket(iface: str) -> socket.socket:
        bridge_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        bridge_socket.bind((iface, 0))
        return bridge_socket

    def _bridge_loop(self) -> None:
        # PACKET_OUTGOING is 4 on Linux; fallback keeps behavior stable if the constant is absent.
        packet_outgoing = getattr(socket, "PACKET_OUTGOING", 4)
        socket_to_port = {bridge_socket: port for port, bridge_socket in self._bridge_sockets.items()}
        sockets = list(socket_to_port)
        while not self._bridge_stop.is_set():
            ready, _, _ = select(sockets, [], [], 0.5)
            for in_socket in ready:
                frame, address = in_socket.recvfrom(65535)
                packet_type = address[2] if len(address) > 2 else None
                if packet_type == packet_outgoing:
                    continue
                in_port = socket_to_port[in_socket]
                result = self.process_frame(in_port, frame)
                out_socket = self._bridge_sockets.get(result["out_port"])
                if out_socket is not None:
                    out_socket.send(result["frame"])

    def start_physical_bridge(self, port1_iface: str, port2_iface: str) -> Dict[int, str]:
        if self.bridge_running:
            raise ValueError("Physical bridge is already running")
        if not port1_iface or not port2_iface:
            raise ValueError("Both interfaces are required")
        if port1_iface == port2_iface:
            raise ValueError("Interfaces for port 1 and port 2 must be different")

        sockets: Dict[int, socket.socket] = {}
        try:
            sockets[1] = self._open_bridge_socket(port1_iface)
            sockets[2] = self._open_bridge_socket(port2_iface)
        except OSError:
            for bridge_socket in sockets.values():
                bridge_socket.close()
            raise
        self._bridge_sockets = sockets
        self._bridge_ifaces = {1: port1_iface, 2: port2_iface}
        self._bridge_stop.clear()
        self._bridge_thread = Thread(target=self._bridge_loop, daemon=True)
        self._bridge_thread.start()
        return self.bridge_interfaces

    def stop_physical_bridge(self) -> None:
        self._bridge_stop.set()
        if self._bridge_thread is not None:
            self._bridge_thread.join(timeout=1.5)
            self._bridge_thread = None
        for bridge_socket in self._bridge_sockets.values():
            bridge_socket.close()
        self._bridge_sockets = {}
        self._bridge_ifaces = {}
