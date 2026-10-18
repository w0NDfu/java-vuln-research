"""Adapt the artifact's {tool, arguments} HTTP protocol to real MCP HTTP."""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

ALLOWED = {"query_knowledge", "get_document", "save_knowledge", "save_result"}
MCP_URL = "http://127.0.0.1:5010/mcp"


async def invoke(tool, arguments, project):
    transport = StreamableHttpTransport(MCP_URL, headers={"project": project} if project else {})
    async with Client(transport, timeout=120) as client:
        result = await client.call_tool(tool, arguments)
        if getattr(result, "is_error", False):
            raise RuntimeError("MCP tool reported an error")
        text = "\n".join(getattr(block, "text", str(block)) for block in result.content)
        if text.lstrip().startswith(("❌", "Error ", "Error:", "Failed to ")):
            raise RuntimeError("Original knowledge tool reported a failure")
        return text


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, data):
        payload = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.send_json(200 if self.path == "/health" else 404, {"ok": self.path == "/health", "service": "vecho-mcp-adapter"})

    def do_POST(self):
        if self.path != "/invoke":
            return self.send_json(404, {"ok": False, "error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1048576:
                return self.send_json(413, {"ok": False, "error": "invalid body size"})
            payload = json.loads(self.rfile.read(length))
            tool = payload.get("tool")
            arguments = payload.get("arguments", {})
            project = self.headers.get("project", "")
            if tool not in ALLOWED or not isinstance(arguments, dict):
                return self.send_json(400, {"ok": False, "error": "unsupported tool or arguments"})
            if project and not re.fullmatch(r"[A-Za-z0-9_-]+", project):
                return self.send_json(400, {"ok": False, "error": "invalid project id"})
            result = asyncio.run(invoke(tool, arguments, project))
            self.send_json(200, {"ok": True, "content": result})
        except Exception as exc:
            # Do not emit provider responses, headers, or credentials to the access log.
            self.send_json(502, {"ok": False, "error": type(exc).__name__ + ": MCP call failed; inspect memory logs"})


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 5011), Handler).serve_forever()
