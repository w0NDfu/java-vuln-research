"""Initialize the actual RAG module offline; no fabricated benchmark result."""
import asyncio
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class OriginalMemoryTests(unittest.TestCase):
    def test_original_rag_and_mcp_tools_initialize_without_network(self):
        # The explicitly offline test key never leaves this temporary test config.
        root = Path(__file__).resolve().parents[1]
        program = '''import asyncio, pathlib, sys, yaml
sys.path.insert(0, sys.argv[1] + "/memory")
from services.mcp_service import MCPService
config = yaml.safe_load(pathlib.Path(sys.argv[1], "memory/config.example.yaml").read_text())
config["rag"]["enable_llm"] = False
config["rag"]["llm"]["enabled"] = False
config["rag"]["embedding"].update(api_key="offline-contract-test", api_base="http://127.0.0.1:9/v1")
pathlib.Path("config.yaml").write_text(yaml.safe_dump(config))
service = MCPService("config.yaml")
tools = asyncio.run(service.mcp.list_tools())
assert {"query_knowledge", "get_document", "save_knowledge", "save_result"}.issubset({tool.name for tool in tools})
assert service.rag_engine.knowledge_base.common_path.exists()
'''
        with tempfile.TemporaryDirectory() as temp:
            process = subprocess.run([sys.executable, "-c", program, str(root)], cwd=temp, env=dict(os.environ, OTEL_SDK_DISABLED="true", ANONYMIZED_TELEMETRY="False"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=90)
            self.assertEqual(process.returncode, 0, process.stdout[-6000:])


if __name__ == "__main__":
    unittest.main()
