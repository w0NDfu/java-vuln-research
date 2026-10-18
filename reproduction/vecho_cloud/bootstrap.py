"""Install an official Go toolchain and prepare reproducible local configuration."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import urllib.request

ROOT = Path("/workspace/vEcho")
REPRO = ROOT / "repro"
REPRO.mkdir(exist_ok=True)
for name in ("logs", "runs", "bin", "targets"):
    (REPRO / name).mkdir(exist_ok=True)

template = """# OpenLux low-cost vEcho configuration. Fill only OPENLUX_API_KEY.
# Adapted-model experiment; not the paper's GPT-4.1 main configuration.
OPENLUX_API_KEY=
VECHO_SCAN_MODEL=gpt-4.1-mini
VECHO_SCAN_BASE_URL=https://api.openlux.ai/v1/chat/completions
VECHO_JUDGE_MODEL=gpt-4.1-mini
VECHO_JUDGE_BASE_URL=https://api.openlux.ai/v1
MEMORY_API_BASE=https://api.openlux.ai/v1
MEMORY_EMBEDDING_MODEL=text-embedding-3-small
MEMORY_LLM_MODEL=gpt-4.1-mini
VECHO_MEMORY_ENABLED=true
VECHO_MEMORY_URL=http://127.0.0.1:5011/invoke
VECHO_MEMORY_TIMEOUT_SECONDS=120
# Sequential context cases reduce peak API concurrency; other scan budgets unchanged.
VECHO_CONTEXT_CONCURRENCY=1
"""
(REPRO / "env.example").write_text(template, encoding="utf-8")
env_path = ROOT / ".env"
if not env_path.exists():
    fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write(template)
print("CONFIG TEMPLATE READY: /workspace/vEcho/.env (credentials not displayed)", flush=True)

# Fix a path error in the published artifact, without changing prompts or models.
config = ROOT / "judge/vecho_judge/app/config.py"
text = config.read_text()
old = 'judge_root = Path(__file__).resolve().parents[2]'
new = 'judge_root = Path(__file__).resolve().parents[1]'
if old in text:
    config.write_text(text.replace(old, new), encoding="utf-8")
elif new not in text:
    raise RuntimeError("Unexpected judge configuration; refusing an unreviewed patch")

# Preserve memory failures instead of converting them into apparent no-hit results.
service = ROOT / "memory/services/mcp_service.py"
text = service.read_text()
old = "                results = self.rag_engine.query(query, project)"
new = old + '\n                if not results.get("success", True):\n                    return "Error querying knowledge base: " + str(results.get("error", "unknown error"))'
if new not in text:
    if old not in text:
        raise RuntimeError("Unexpected memory service; refusing an unreviewed patch")
    text = text.replace(old, new, 1)
old = "                        self.rag_engine.update_knowledge_base(target_project)"
new = '                        if not self.rag_engine.update_knowledge_base(target_project):\n                            return "Error saving knowledge: index update failed"'
if old in text:
    text = text.replace(old, new, 1)
service.write_text(text, encoding="utf-8")

toolchains = Path("/workspace/toolchains")
toolchains.mkdir(exist_ok=True)
go = toolchains / "go/bin/go"
if not go.exists():
    releases = json.load(urllib.request.urlopen("https://go.dev/dl/?mode=json", timeout=60))
    release = next(item for item in releases if item["stable"])
    asset = next(item for item in release["files"] if item["os"] == "linux" and item["arch"] == "amd64" and item["kind"] == "archive")
    archive = toolchains / asset["filename"]
    print("DOWNLOADING official Go " + release["version"], flush=True)
    urllib.request.urlretrieve("https://go.dev/dl/" + asset["filename"], archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != asset["sha256"]:
        raise RuntimeError("Official Go archive checksum mismatch")
    subprocess.run(["tar", "-xzf", str(archive), "-C", str(toolchains)], check=True)
    (REPRO / "go-provenance.json").write_text(json.dumps({"version": release["version"], "asset": asset}, indent=2))
env = dict(os.environ, PATH=str(toolchains / "go/bin") + ":" + os.environ["PATH"], GOROOT=str(toolchains / "go"), GOTOOLCHAIN="local")
subprocess.run([str(go), "version"], env=env, check=True)
with (REPRO / "logs/go-tests.log").open("w") as output:
    subprocess.run([str(go), "test", "./..."], cwd=ROOT / "scaner", env=env, stdout=output, stderr=subprocess.STDOUT, check=True)
subprocess.run([str(go), "build", "-o", str(REPRO / "bin/vecho-scan"), "./cmd/vecho-scan"], cwd=ROOT / "scaner", env=env, check=True)
print("GO TESTS PASSED; SCANNER BUILT", flush=True)
