"""Migrate non-secret settings; retain any existing credential without printing it."""
import ast
import json
import os
from pathlib import Path

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
REPRO = ROOT / "repro"
tree = ast.parse((REPRO / "bootstrap.py").read_text())
template = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "template" for target in node.targets))
env_path = ROOT / ".env"
old = dotenv_values(env_path) if env_path.exists() else {}
key = old.get("OPENLUX_API_KEY") or ""
legacy_keys = {old.get(name) for name in ("SILICONFLOW_API_KEY", "MEMORY_API_KEY", "VECHO_SCAN_API_KEY", "VECHO_JUDGE_API_KEY") if old.get(name)}
if not key and len(legacy_keys) > 1:
    raise RuntimeError("Multiple different legacy credentials found; existing .env left untouched")
if not key and legacy_keys:
    key = legacy_keys.pop()
text = template.replace("OPENLUX_API_KEY=", "OPENLUX_API_KEY=" + json.dumps(key), 1) if key else template
known = set(dotenv_values(stream=__import__("io").StringIO(template)))
legacy = {"SILICONFLOW_API_KEY", "MEMORY_API_KEY", "VECHO_SCAN_API_KEY", "VECHO_JUDGE_API_KEY"}
extras = {name:value for name,value in old.items() if name not in known | legacy}
for name, value in extras.items():
    text += name + "=" + json.dumps(value or "", ensure_ascii=False) + "\n"
temp = env_path.with_name(".env.configuring")
fd = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
with os.fdopen(fd, "w") as output:
    output.write(text)
os.chmod(temp, 0o600)
temp.replace(env_path)
(REPRO / "env.example").write_text(template, encoding="utf-8")
print("OpenLux settings saved. Single key field: OPENLUX_API_KEY.")
print("Credential present:", bool(key), "(value not displayed)")
print("Scan/judge/memory LLM: gpt-4.1-mini; embedding: text-embedding-3-small")
