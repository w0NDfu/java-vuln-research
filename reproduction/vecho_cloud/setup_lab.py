"""Prepare a pinned vEcho checkout inside one Linux experiment directory.

This command prepares files only; it never starts model requests.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

PIN = "68da10388878f8626f0a1d124e500c979ac1e82d"


def run(args, **kwargs):
    subprocess.run([str(x) for x in args], check=True, **kwargs)


def replace_once(path, before, after):
    text = path.read_text(encoding="utf-8")
    if after in text:
        return
    if text.count(before) != 1:
        raise RuntimeError("Unexpected upstream source: " + str(path))
    path.write_text(text.replace(before, after, 1), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--skip-dependencies", action="store_true")
    parser.add_argument("--skip-dataset", action="store_true")
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    if os.name != "posix" or root == Path("/"):
        parser.error("Use a dedicated experiment directory on Linux")
    root.mkdir(parents=True, exist_ok=True)
    artifact = root / "vEcho"
    env = dict(os.environ)
    for name, relative in {
        "UV_CACHE_DIR": "cache/uv", "UV_PYTHON_INSTALL_DIR": "toolchains/python",
        "GOCACHE": "cache/go-build", "GOMODCACHE": "cache/go-mod",
        "XDG_CACHE_HOME": "cache", "HF_HOME": "cache/huggingface",
        "TIKTOKEN_CACHE_DIR": "cache/tiktoken", "TMPDIR": "tmp",
    }.items():
        path = root / relative
        path.mkdir(parents=True, exist_ok=True)
        env[name] = str(path)
    env["VECHO_DATASET"] = str(root / "dataset")
    env["GOMAXPROCS"] = "8"
    for relative in ["logs", "migration", "dataset"]:
        (root / relative).mkdir(exist_ok=True)
    if not artifact.exists():
        run(["git", "clone", "https://github.com/vEcho-project/vEcho.git", artifact], env=env)
        run(["git", "-C", artifact, "checkout", "--detach", PIN], env=env)
    sha = subprocess.check_output(["git", "-C", str(artifact), "rev-parse", "HEAD"], text=True).strip()
    if sha != PIN:
        raise RuntimeError("Existing artifact is at a different commit; no reset performed")
    helpers = Path(__file__).resolve().parent
    repro = artifact / "repro"
    repro.mkdir(exist_ok=True)
    for source in helpers.iterdir():
        if source.is_file() and source.suffix in {".py", ".md", ".txt"}:
            target = repro / source.name
            if source.resolve() != target.resolve():
                shutil.copy2(source, target)
    for name in ["logs", "runs", "bin", "targets"]:
        (repro / name).mkdir(exist_ok=True)
    template = (helpers / "env.example").read_text(encoding="utf-8")
    env_path = artifact / ".env"
    if not env_path.exists():
        fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(template)
    replace_once(artifact / "judge/vecho_judge/app/config.py",
                 'judge_root = Path(__file__).resolve().parents[2]',
                 'judge_root = Path(__file__).resolve().parents[1]')
    service = artifact / "memory/services/mcp_service.py"
    query = "                results = self.rag_engine.query(query, project)"
    replace_once(service, query, query + '\n                if not results.get("success", True):\n                    return "Error querying knowledge base: " + str(results.get("error", "unknown error"))')
    replace_once(service,
                 "                        self.rag_engine.update_knowledge_base(target_project)",
                 '                        if not self.rag_engine.update_knowledge_base(target_project):\n                            return "Error saving knowledge: index update failed"')
    uv = shutil.which("uv")
    if not uv:
        raise RuntimeError("Install uv from its official distribution first")
    python = root / ".venv/bin/python"
    if not python.exists():
        run([uv, "python", "install", "3.11.12"], env=env)
        run([uv, "venv", "--python", "3.11.12", "--managed-python", root / ".venv"], env=env)
    if not args.skip_dependencies:
        run([uv, "pip", "install", "--python", python,
             "-r", artifact / "judge/requirements.txt",
             "-r", artifact / "memory/requirements.txt",
             "-c", repro / "evaluator-constraints.txt",
             "tree-sitter==0.25.2", "tree-sitter-java==0.23.5"], env=env)
        freeze = subprocess.check_output([uv, "pip", "freeze", "--python", str(python)], env=env, text=True)
        (root / "migration/lab-freeze.txt").write_text(freeze, encoding="utf-8")
    run([python, repro / "patch_judge_budget.py"], cwd=artifact, env=env)
    go = shutil.which("go")
    if not go and Path("/usr/local/go/bin/go").exists():
        go = "/usr/local/go/bin/go"
    if not go:
        raise RuntimeError("Install Go >=1.22 from its official distribution first")
    version = subprocess.check_output([go, "version"], text=True).strip()
    with (root / "logs/go-build.log").open("w") as output:
        run([go, "build", "-o", repro / "bin/vecho-scan", "./cmd/vecho-scan"],
            cwd=artifact / "scaner", env=env, stdout=output, stderr=subprocess.STDOUT)
    # The dataset must be exported before common.py is imported.
    exports = {key: value for key, value in env.items() if key in {
        "UV_CACHE_DIR", "UV_PYTHON_INSTALL_DIR", "GOCACHE", "GOMODCACHE",
        "XDG_CACHE_HOME", "HF_HOME", "TIKTOKEN_CACHE_DIR", "TMPDIR", "VECHO_DATASET"}}
    launcher = "#!/usr/bin/env bash\nset -euo pipefail\n"
    launcher += "".join("export " + key + "=" + shlex.quote(value) + "\n" for key, value in exports.items())
    launcher += "cd " + shlex.quote(str(artifact)) + "\n"
    launcher += 'exec ' + shlex.quote(str(python)) + ' "$@"\n'
    (root / "python.sh").write_text(launcher, encoding="utf-8")
    (root / "python.sh").chmod(0o700)
    if not args.skip_dataset:
        run([python, repro / "clone_dataset.py", "--artifact", artifact,
             "--dataset", root / "dataset", "--workers", "4"], env=env)
    (root / "migration/setup-provenance.json").write_text(json.dumps({
        "artifact_commit": sha, "go_version": version, "root": str(root),
        "models_started": False, "dependency_install_skipped": args.skip_dependencies,
        "dataset_verification_skipped": args.skip_dataset,
    }, indent=2), encoding="utf-8")
    print("Prepared", root, "(no model requests started)")


if __name__ == "__main__":
    main()
