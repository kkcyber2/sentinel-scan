import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


def _make_handler(headers: dict[str, str], body: str, status: int = 200):
    class Handler(BaseHTTPRequestHandler):
        # Suppress the Server header BaseHTTPRequestHandler adds by default, so a
        # test can control exactly which headers the scanner sees.
        def version_string(self):  # noqa: D102
            return ""

        def do_GET(self):  # noqa: N802
            payload = body.encode()
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):  # silence the test server
            return

    return Handler


@pytest.fixture()
def serve():
    """Start a throwaway HTTP server and yield a factory for its URL."""
    servers = []

    def start(headers: dict[str, str], body: str = "<html>ok</html>", status: int = 200) -> str:
        server = HTTPServer(("127.0.0.1", 0), _make_handler(headers, body, status))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_port}/"

    yield start
    for server in servers:
        server.shutdown()
