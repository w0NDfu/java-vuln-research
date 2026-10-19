"""Read-only input readiness check; no model requests, services or builds."""
import importlib.util
import os
import subprocess
from pathlib import Path
from .runner import projects
from .io import file_hash


def check(cfg):
    errors, warnings, sources = [], [], []
    for name in ["tree_sitter", "tree_sitter_java", "yaml", "openai"]:
        if importlib.util.find_spec(name) is None: errors.append("Missing Python dependency: " + name)
    if cfg["memory"]["policy"] != "disabled":
        if importlib.util.find_spec("llama_index") is None: errors.append("Full memory dependencies are not installed")
    try:
        rows = projects(cfg)
    except Exception as exc:
        return {"ready": False, "errors": ["Dataset metadata unavailable: " + type(exc).__name__], "warnings": [], "model_requests_started": False}
    for row in rows:
        root = Path(cfg["dataset"]) / "project-sources" / row["project_slug"]
        try:
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True, stderr=subprocess.DEVNULL).strip()
            if commit != row["buggy_commit_id"]: errors.append("Source commit mismatch for sample " + row["id"])
        except (OSError, subprocess.CalledProcessError):
            errors.append("Source checkout missing for sample " + row["id"])
        for spec in cfg["static_sources"]:
            path = Path(cfg["config_dir"]) / spec["path"].format(id=row["id"], sample=f"sample_{int(row['id']):04d}")
            if spec.get("commands"):
                if not spec.get("version_command"): errors.append("Static producer version_command missing: " + spec["tool"])
                mode = "generate_on_execute"
            else:
                mode = "import"
                if not path.is_file() and spec.get("required", True): errors.append("Missing required report: " + str(path))
            if "CONFIGURE" in spec["version"] or "CONFIGURE" in str(spec["queries"]): errors.append("Configure actual producer/query provenance: " + spec["tool"])
            for query in spec.get("query_files", []):
                if not (Path(cfg["config_dir"]) / query).is_file(): errors.append("Missing pinned query input: " + query)
            sources.append({"sample": row["id"], "tool": spec["tool"], "mode": mode, "sha256": file_hash(path) if path.is_file() else None})
    for role, model in cfg["models"].items():
        if not os.environ.get(model["key_env"]): errors.append("Credential environment variable absent for " + role)
        if model["input_usd_per_million"] <= 0 or role != "embedding" and model["output_usd_per_million"] <= 0:
            errors.append("Actual positive prices required for " + role)
    if cfg["budget"]["limit_usd"] <= cfg["budget"]["opening_spend_usd"] or cfg["budget"]["max_requests"] < 1:
        errors.append("No remaining cumulative execution budget/request count configured")
    if not (Path(cfg["workspace"]) / "runtime/runtime.json").is_file(): errors.append("Isolated runtime not prepared")
    warnings += ["Anonymization and scoring are reconstructed, not the authors' historical scripts.",
                 "Opening spend, prices and historical missing materials require operator verification."]
    return {"ready": not errors, "errors": sorted(set(errors)), "warnings": warnings, "static_inputs": sources, "model_requests_started": False}
