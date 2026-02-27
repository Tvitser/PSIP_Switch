import unittest
from unittest.mock import patch

from software_switch import SoftwareSwitch


class TestSoftwareSwitch(unittest.TestCase):
    def setUp(self) -> None:
        self.switch = SoftwareSwitch()

    def _tcp_http_frame(self) -> bytes:
        dst = bytes.fromhex("001122334455")
        src = bytes.fromhex("66778899aabb")
        ethertype = bytes.fromhex("0800")

        ip_header = bytes(
            [
                0x45,
                0x00,
                0x00,
                0x3C,
                0x00,
                0x00,
                0x00,
                0x00,
                0x40,
                0x06,
                0x00,
                0x00,
                192,
                168,
                0,
                2,
                192,
                168,
                0,
                1,
            ]
        )

        tcp_header = bytes.fromhex("3039005000000000000000005018000000000000")
        payload = b"GET / HTTP/1.1\r\n"
        return dst + src + ethertype + ip_header + tcp_header + payload

    def test_process_frame_forwards_to_other_port_and_counts_protocols(self) -> None:
        frame = self._tcp_http_frame()
        result = self.switch.process_frame(1, frame)

        self.assertEqual(result["out_port"], 2)
        self.assertIn("ethernet_ii", result["protocols"])
        self.assertIn("ip", result["protocols"])
        self.assertIn("tcp", result["protocols"])
        self.assertIn("http", result["protocols"])

        self.assertEqual(self.switch.stats[1].rx_frames, 1)
        self.assertEqual(self.switch.stats[2].tx_frames, 1)
        self.assertEqual(self.switch.stats[1].rx_pdus["http"], 1)
        self.assertEqual(self.switch.stats[2].tx_pdus["http"], 1)

    def test_mac_learning_selects_known_destination_port(self) -> None:
        frame1 = self._tcp_http_frame()
        self.switch.process_frame(1, frame1)

        dst = bytes.fromhex("66778899aabb")
        src = bytes.fromhex("001122334455")
        ethertype = bytes.fromhex("0806")
        arp_payload = bytes(28)
        frame2 = dst + src + ethertype + arp_payload

        result = self.switch.process_frame(2, frame2)
        self.assertEqual(result["out_port"], 1)
        self.assertEqual(self.switch.stats[2].rx_pdus["arp"], 1)
        self.assertEqual(self.switch.stats[1].tx_pdus["arp"], 1)

    def test_reset_statistics_clears_all_counters(self) -> None:
        self.switch.process_frame(1, self._tcp_http_frame())
        self.switch.reset_statistics()

        for port in (1, 2):
            self.assertEqual(self.switch.stats[port].rx_frames, 0)
            self.assertEqual(self.switch.stats[port].tx_frames, 0)
            for value in self.switch.stats[port].rx_pdus.values():
                self.assertEqual(value, 0)
            for value in self.switch.stats[port].tx_pdus.values():
                self.assertEqual(value, 0)

    def test_available_interfaces_excludes_loopback(self) -> None:
        with patch("software_switch.socket.if_nameindex", return_value=[(1, "lo"), (2, "eth0"), (3, "enp0s20f0u1")]):
            self.assertEqual(SoftwareSwitch.available_interfaces(), ["enp0s20f0u1", "eth0"])

    def test_available_interfaces_empty(self) -> None:
        with patch("software_switch.socket.if_nameindex", return_value=[]):
            self.assertEqual(SoftwareSwitch.available_interfaces(), [])

    def test_start_physical_bridge_requires_two_distinct_interfaces(self) -> None:
        with self.assertRaisesRegex(ValueError, "Both interfaces are required"):
            self.switch.start_physical_bridge("", "eth1")
        with self.assertRaisesRegex(ValueError, "must be different"):
            self.switch.start_physical_bridge("eth1", "eth1")


if __name__ == "__main__":
    unittest.main()
