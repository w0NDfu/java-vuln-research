"""Real MCP transport contract test, without calling an external model."""
import asyncio
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import memory_bridge


class BridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        fixture = Path(cls.temp.name) / "fixture.py"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        fixture.write_text('''from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers
mcp = FastMCP("transport-contract-fixture")
@mcp.tool
def query_knowledge(query: str) -> str:
    return get_http_headers().get("project", "") + "|" + query
if __name__ == "__main__":
    mcp.run(transport="http", host="127.0.0.1", port=''' + str(port) + ''')
''')
        cls.process = subprocess.Popen([sys.executable, str(fixture)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        memory_bridge.MCP_URL = f"http://127.0.0.1:{port}/mcp"
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if cls.process.poll() is not None:
                    raise RuntimeError("MCP fixture startup failed")
                time.sleep(0.1)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), memory_bridge.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/invoke"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.process.terminate()
        cls.process.wait(timeout=10)
        cls.temp.cleanup()

    def test_original_judge_client_with_real_mcp_transport(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "judge"))
        from vecho_judge.memory_client.client import MemoryClient
        errors = []
        client = MemoryClient(enabled=True, url=self.url, project="sample_0002", errors=errors)
        self.assertEqual(client.query_knowledge("hello"), "sample_0002|hello")
        self.assertEqual(errors, [])

    def test_unknown_tools_are_rejected_before_mcp(self):
        request = Request(self.url, data=json.dumps({"tool":"unknown", "arguments":{}}).encode(), headers={"Content-Type":"application/json"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        self.assertEqual(caught.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
