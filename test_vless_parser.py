import struct
import uuid
import unittest

from relay_vless import VLESSNeedMoreData, parse_vless_header


class VlessParserTests(unittest.TestCase):
    def setUp(self):
        self.uid = uuid.uuid4().bytes
        host = b"example.com"
        self.header = (
            bytes([0]) + self.uid + bytes([0]) + bytes([1]) +
            struct.pack(">H", 443) + bytes([2, len(host)]) + host +
            b"payload"
        )

    def test_full_header(self):
        command, address, port, payload = parse_vless_header(self.header)
        self.assertEqual(command, 1)
        self.assertEqual(address, "example.com")
        self.assertEqual(port, 443)
        self.assertEqual(payload, b"payload")

    def test_every_short_prefix_is_incomplete(self):
        header_end = len(self.header) - len(b"payload")
        for size in range(1, header_end):
            with self.assertRaises(VLESSNeedMoreData):
                parse_vless_header(self.header[:size])

    def test_ipv4(self):
        h = (
            bytes([0]) + self.uid + b"\0" + bytes([1]) +
            struct.pack(">H", 80) + bytes([1, 127, 0, 0, 1])
        )
        self.assertEqual(parse_vless_header(h)[1:3], ("127.0.0.1", 80))


if __name__ == "__main__":
    unittest.main()
