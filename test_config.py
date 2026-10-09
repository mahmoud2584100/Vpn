import unittest
import uuid

from main import generate_vless_link


class LinkGenerationTests(unittest.TestCase):
    def test_xhttp_defaults_to_proxy_compatible_packet_up(self):
        uid = str(uuid.uuid4())
        link = generate_vless_link(uid, "example.blitz.cloud", protocol="xhttp")
        self.assertIn("type=xhttp", link)
        self.assertIn("mode=packet-up", link)
        self.assertIn("alpn=http/1.1", link)
        self.assertIn(f"path=/xhttp-siz10/{uid}", link)

    def test_websocket_keeps_http11_default(self):
        uid = str(uuid.uuid4())
        link = generate_vless_link(uid, "example.blitz.cloud", protocol="vless-ws")
        self.assertIn("type=ws", link)
        self.assertIn("alpn=http/1.1", link)
        self.assertIn(f"path=/ws/{uid}", link)


if __name__ == "__main__":
    unittest.main()
