"""Install the reviewed scanner overlay; never start models or overwrite runs."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def digest(data):
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def install(artifact, source=None):
    artifact = Path(artifact).resolve()
    source = Path(source) if source is not None else Path(__file__).resolve().parent / "scanner_overlay"
    manifest = json.loads((source / "manifest.json").read_text())
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=artifact, text=True).strip()
    if actual != manifest["artifact_commit"]:
        raise RuntimeError("Unexpected artifact revision; no files changed")
    changes = []
    # Verify every source and destination before the first mutation.
    for relative, expected in manifest["files"].items():
        payload = (source / relative).read_bytes().replace(b"\r\n", b"\n")
        if digest(payload) != expected["patched_sha256"]:
            raise RuntimeError("Overlay integrity mismatch: " + relative)
        target = artifact / "scaner" / relative
        if not target.resolve().is_relative_to((artifact / "scaner").resolve()):
            raise RuntimeError("Unsafe overlay path")
        current = digest(target.read_bytes()) if target.exists() else None
        if current == expected["patched_sha256"]:
            continue
        if current != expected["original_sha256"] and current not in expected.get("accepted_previous_sha256", []):
            raise RuntimeError("Unrecognized local scanner changes: " + relative)
        changes.append((relative, target, payload))
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = artifact / "repro/scanner-backups" / stamp
    if changes:
        backup.mkdir(parents=True, exist_ok=False)
    for relative, target, payload in changes:
        if target.exists():
            old = backup / relative
            old.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, old)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".repair-tmp")
        temporary.write_bytes(payload)
        temporary.replace(target)
    record = {"installed_at": stamp, "artifact_commit": actual, "changed_files": [r for r, _, _ in changes],
              "backup": str(backup), "models_started": False, "manifest_sha256": digest((source / "manifest.json").read_bytes())}
    if changes:
        (backup / "installation.json").write_text(json.dumps(record, indent=2))
        (artifact / "repro/scanner-repair-installation.json").write_text(json.dumps(record, indent=2))
    print(json.dumps(record, indent=2))
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    install(parser.parse_args().artifact)
