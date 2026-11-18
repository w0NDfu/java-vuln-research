import copy
import subprocess
from pathlib import Path
from reproduction.vecho_experiment.config import DEFAULTS


def config(root):
    root = Path(root)
    c = copy.deepcopy(DEFAULTS)
    c.update(profile="ablation", require_static=False, artifact=str(root / "artifact"), dataset=str(root / "dataset"),
             workspace=str(root / "experiment"), config_dir=str(root))
    c["memory"]["policy"] = "disabled"
    c["models"] = {role: {"model": "offline-fixture" if role != "embedding" else "text-embedding-ada-002",
                    "base_url": "https://provider.invalid/v1", "key_env": "VECHO_TEST_KEY",
                    "context_tokens": 1000, "max_output_tokens": 100,
                    "input_usd_per_million": 1, "output_usd_per_million": 2,
                    "sampling": {"temperature": 0.1}} for role in ["scan", "judge", "memory", "embedding"]}
    c["budget"].update(limit_usd=1, max_requests=100)
    return c


def finding(line=3, rule="rule", tool="CodeQL"):
    return {"fingerprint": "original", "description": "test finding", "short_description": rule,
            "category": rule, "source_scanner": tool,
            "affected_files": [{"file_path": "A.java", "line_numbers": [line]}],
            "tainted_data_flow": [[{"file_path": "A.java", "line_number": line, "description": "fixture"}]], "metadata": {}}


def git_repo(path):
    path = Path(path); path.mkdir(parents=True)
    (path / "A.java").write_text("class A {\n void vulnerable() {\n  dangerous();\n }\n void safe() {\n  harmless();\n }\n}\n", encoding="utf-8")
    for command in [["init", "-q"], ["add", "."], ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"]]:
        subprocess.run(["git", *command], cwd=path, check=True, capture_output=True)
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
