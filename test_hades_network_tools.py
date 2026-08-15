import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from hades_network_tools import PortScanManager, send_test_payload


class EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlsplit(self.path).query)
        body = query.get("test", [""])[0].encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class NetworkToolTests(unittest.TestCase):
    def test_payload_sender_sends_parameter_and_captures_evidence(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = send_test_payload(
                f"http://127.0.0.1:{server.server_port}/echo", "GET", "test", "probe")
            self.assertEqual(result["status_code"], 200)
            self.assertEqual(result["response_excerpt"], "probe")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_port_scan_reports_listening_port(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        try:
            manager = PortScanManager(workers=2)
            job = manager.start("127.0.0.1", port, port, 100)
            deadline = time.time() + 3
            while job["status"] in {"queued", "running"} and time.time() < deadline:
                time.sleep(0.02)
                job = manager.get(job["id"])
            self.assertEqual(job["status"], "completed")
            self.assertEqual([item["port"] for item in job["open_ports"]], [port])
            self.assertEqual(job["progress"], 100.0)
        finally:
            listener.close()


if __name__ == "__main__":
    unittest.main()
