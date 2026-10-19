"""Build an isolated, pinned runtime without touching upstream or old runs."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
from .config import PIN
from .io import read, write, file_hash, tree_hash, now

HELPERS = Path(__file__).resolve().parents[1] / "vecho_cloud"


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec); spec.loader.exec_module(obj)
    return obj


def prepare(cfg):
    root = Path(cfg["workspace"]) / "runtime"
    if root.exists(): raise ValueError("Runtime exists; it will never be overwritten")
    original = Path(cfg["artifact"])
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=original, text=True).strip()
    if sha != PIN or subprocess.check_output(["git", "status", "--porcelain"], cwd=original, text=True).strip():
        raise ValueError("Provide a clean upstream checkout at the pinned commit")
    root.mkdir(parents=True)
    artifact = root / "artifact"
    subprocess.run(["git", "clone", "--no-hardlinks", str(original), str(artifact)], check=True, capture_output=True)
    installer = module(HELPERS / "apply_scanner_repair.py", "vecho_scanner_installer")
    installer.install(artifact)
    if cfg["judge"]["final_save_adapter"]:
        # This adapter changes termination behavior and is an explicit variant.
        sys.path.insert(0, str(HELPERS))
        adapter = module(HELPERS / "patch_judge_budget.py", "vecho_judge_adapter")
        path = artifact / "judge/vecho_judge/runtime/llm_loop.py"
        before = path.read_text(encoding="utf-8")
        path.with_suffix(".py.upstream").write_text(before, encoding="utf-8")
        path.write_text(adapter.patch(before), encoding="utf-8")
    binary = root / ("vecho-scan.exe" if os.name == "nt" else "vecho-scan")
    go = shutil.which("go")
    if not go: raise RuntimeError("Go >=1.22 is required to build scanner")
    with (root / "go-build.log").open("wb") as out:
        subprocess.run([go, "build", "-o", str(binary), "./cmd/vecho-scan"], cwd=artifact / "scaner", stdout=out, stderr=subprocess.STDOUT, check=True)
    record = {"prepared_at": now(), "upstream": PIN, "artifact": str(artifact), "scanner_binary": str(binary),
              "scanner_sha256": file_hash(binary), "source_tree_sha256": tree_hash(artifact),
              "judge_final_save_adapter": cfg["judge"]["final_save_adapter"],
              "go_version": subprocess.check_output([go, "version"], text=True).strip(),
              "python_version": sys.version, "model_requests_started": False}
    write(root / "runtime.json", record)
    return record


def verify(cfg):
    record = read(Path(cfg["workspace"]) / "runtime/runtime.json")
    if record["upstream"] != PIN or record["judge_final_save_adapter"] != cfg["judge"]["final_save_adapter"]:
        raise ValueError("Runtime variant does not match experiment")
    if file_hash(record["scanner_binary"]) != record["scanner_sha256"] or tree_hash(record["artifact"]) != record["source_tree_sha256"]:
        raise ValueError("Runtime changed since preparation")
    return record
