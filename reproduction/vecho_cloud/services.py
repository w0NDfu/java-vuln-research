"""Start the original RAG service plus the protocol adapter on loopback only."""
import json
import os
import secrets
import subprocess
import sys
import time
from urllib.request import urlopen

from common import ROOT, REPRO, load_env, required, write_json


def configure():
    import yaml
    load_env()
    key = required("MEMORY_API_KEY")
    config = yaml.safe_load((ROOT / "memory/config.example.yaml").read_text())
    config["system"]["host"] = "127.0.0.1"
    for section, model_var, fallback in [("embedding", "MEMORY_EMBEDDING_MODEL", "text-embedding-3-small"), ("llm", "MEMORY_LLM_MODEL", "gpt-4.1-mini")]:
        config["rag"][section].update(api_key=key, api_base=os.environ.get("MEMORY_API_BASE", "https://api.openlux.ai/v1"), model=os.environ.get(model_var, fallback))
    config["auth"].update(password=secrets.token_urlsafe(32), secret_key=secrets.token_urlsafe(32))
    # Record this explicit configuration choice. Original default stages knowledge for
    # manual approval; direct indexing is needed for an automated learning loop.
    config["save_tools"] = {"use_tmp": False}
    path = ROOT / "memory/config.yaml"
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as output:
        yaml.safe_dump(config, output)
    write_json(REPRO / "memory-settings.json", {"host": "127.0.0.1", "mcp_port": 5010, "bridge_port": 5011, "direct_knowledge_indexing": True, "initial_knowledge": "empty; no ground-truth ingestion", "embedding_model": config["rag"]["embedding"]["model"], "llm_model": config["rag"]["llm"]["model"]})


def start():
    configure()
    processes = {}
    for name, args, cwd in [
        ("memory", [sys.executable, "main.py", "--service", "mcp", "--config", "config.yaml", "--mcp-host", "127.0.0.1"], ROOT / "memory"),
        ("memory-bridge", [sys.executable, str(REPRO / "memory_bridge.py")], ROOT),
    ]:
        with (REPRO / "logs" / (name + ".log")).open("a") as output:
            proc = subprocess.Popen(args, cwd=cwd, stdout=output, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
            processes[name] = proc.pid
    write_json(REPRO / "service-pids.json", processes)
    for _ in range(60):
        try:
            with urlopen("http://127.0.0.1:5011/health", timeout=2) as response:
                if response.status == 200:
                    # Check the actual MCP service, not just the adapter process.
                    import asyncio
                    from fastmcp import Client
                    async def probe():
                        async with Client("http://127.0.0.1:5010/mcp") as client:
                            return [tool.name for tool in await client.list_tools()]
                    tools = asyncio.run(probe())
                    assert {"query_knowledge", "get_document", "save_knowledge", "save_result"}.issubset(tools)
                    print("Memory MCP and adapter ready", flush=True)
                    return
        except Exception:
            time.sleep(1)
    raise RuntimeError("Memory services did not become ready; inspect repro/logs")


if __name__ == "__main__":
    start()
