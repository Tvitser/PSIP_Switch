import unittest

from software_switch_gui import parse_hex_frame


class TestSoftwareSwitchGuiHelpers(unittest.TestCase):
    def test_parse_hex_frame_accepts_whitespace(self) -> None:
        frame = parse_hex_frame("00 11 22 33\n44 55")
        self.assertEqual(frame, bytes.fromhex("001122334455"))

    def test_parse_hex_frame_rejects_odd_length(self) -> None:
        with self.assertRaises(ValueError):
            parse_hex_frame("001")

    def test_parse_hex_frame_rejects_invalid_hex(self) -> None:
        with self.assertRaisesRegex(ValueError, "^Frame hex string contains invalid hexadecimal characters$"):
            parse_hex_frame("gg")


if __name__ == "__main__":
    unittest.main()
