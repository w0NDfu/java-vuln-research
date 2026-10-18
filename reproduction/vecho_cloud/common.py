"""Cloud-only reproduction helpers; never print credentials."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPRO = ROOT / "repro"
DATASET = Path(os.environ.get("VECHO_DATASET", "/workspace/dataset"))


def load_env():
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env", override=False)
    apply_shared_key()


def apply_shared_key():
    """One OpenLux credential feeds all upstream-compatible variable names."""
    shared = os.environ.get("OPENLUX_API_KEY", "").strip()
    if shared:
        for name in ("SILICONFLOW_API_KEY", "VECHO_SCAN_API_KEY", "VECHO_JUDGE_API_KEY", "MEMORY_API_KEY"):
            os.environ[name] = shared


def required(name):
    value = os.environ.get(name, "").strip()
    if not value or value.startswith("YOUR_"):
        field = "OPENLUX_API_KEY" if name in {"SILICONFLOW_API_KEY", "VECHO_SCAN_API_KEY", "VECHO_JUDGE_API_KEY", "MEMORY_API_KEY"} else name
        raise RuntimeError(f"Configure {field} in {ROOT / '.env'}; no live model requests made")
    return value


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def samples():
    import csv
    with (DATASET / "metadata/project_info.csv").open(encoding="utf-8-sig") as file:
        return list(csv.DictReader(file))
