"""Export pinned Git content; transformations preserve every line and byte offset."""
import io
import posixpath
import re
import subprocess
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path
from .io import digest, file_hash, tree_hash, write, inside


class Redactor:
    def __init__(self, tokens=()):
        self.tokens = sorted(set(x.encode() for x in tokens if len(x.encode()) >= 3), key=len, reverse=True)

    def mask(self, value):
        data = value if isinstance(value, bytes) else value.encode()
        def replace(m):
            raw = m.group()
            # ASCII substitutions of identical byte length preserve line/column.
            return b"X" * len(raw)
        data = re.sub(rb"(?i)CVE-\d{4}-\d{4,}|\b[0-9a-f]{40}\b", replace, data)
        for token in self.tokens:
            data = re.sub(re.escape(token), replace, data, flags=re.I)
        return data if isinstance(value, bytes) else data.decode()

    def report(self, records):
        import copy
        records = copy.deepcopy(records)
        # Keep schema keys, normalized paths and numeric locations intact.
        for r in records:
            for k in ["description", "short_description", "category"]:
                if k in r: r[k] = self.mask(str(r[k] or ""))
            for flow in r.get("tainted_data_flow", []):
                for n in flow:
                    n["description"] = self.mask(str(n.get("description") or ""))
            # Raw metadata stays private; it may contain CVEs, source roots,
            # fix commits, URLs or SARIF properties. Origins are in receipts.
            r["metadata"] = {"experiment_candidate_id": r["fingerprint"]}
        return records


def export(source, commit, target, private, policy, project):
    source, target, private = Path(source).resolve(), Path(target), Path(private)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if actual != commit:
        raise ValueError("Dataset checkout does not match vulnerable commit")
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=source, text=True).strip():
        raise ValueError("Dataset has tracked modifications")
    if any(line.startswith("160000 ") for line in subprocess.check_output(["git", "ls-files", "--stage"], cwd=source, text=True).splitlines()):
        raise ValueError("Submodule content must first be pinned into a self-contained input snapshot")
    if target.exists():
        raise ValueError("Snapshot already exists; verify stage receipt before reuse")
    archive = subprocess.check_output(["git", "archive", commit], cwd=source)
    tokens = list(policy["tokens"])
    if policy["enabled"]:
        tokens += [project.get("github_username", ""), project.get("github_repository_name", "")]
    with tarfile.open(fileobj=io.BytesIO(archive)) as tf:
        members = tf.getmembers()
        dependency_tokens = []
        if policy["enabled"] and policy["redact_dependency_coordinates"]:
            for m in members:
                if m.isfile() and m.name.endswith("pom.xml"):
                    try:
                        doc = ET.fromstring(tf.extractfile(m).read())
                        dependency_tokens += [(e.text or "").strip() for e in doc.iter() if e.tag.split("}")[-1] in {"artifactId", "groupId", "name"}]
                    except ET.ParseError:
                        pass
        redactor = Redactor(tokens if policy["enabled"] else [])
        pom_redactor = Redactor(tokens + dependency_tokens)
        by_name = {m.name.rstrip("/"): m for m in members}
        def file_member(m, seen=()):
            if m.name in seen: raise ValueError("Cyclic source symlink")
            if m.issym():
                link = posixpath.normpath(posixpath.join(posixpath.dirname(m.name), m.linkname))
                if link.startswith(("../", "/")) or link not in by_name: raise ValueError("Source link escapes snapshot")
                return file_member(by_name[link], seen + (m.name,))
            if not m.isfile(): raise ValueError("Unsupported source archive entry")
            return m
        target.mkdir(parents=True)
        entries = []
        for m in members:
            p = inside(target, m.name)
            if m.isdir():
                p.mkdir(parents=True, exist_ok=True); continue
            actual_member = file_member(m)
            data = tf.extractfile(actual_member).read()
            transformed = data
            if policy["enabled"] and b"\0" not in data:
                transformed = (pom_redactor if m.name.endswith("pom.xml") else redactor).mask(data)
            if len(transformed) != len(data) or transformed.count(b"\n") != data.count(b"\n"):
                raise ValueError("Anonymization changed source offsets")
            p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(transformed)
            p.chmod(m.mode & 0o777)
            entries.append({"path": m.name, "before": digest(data), "after": file_hash(p), "changed": data != transformed,
                            "materialized_link": m.linkname if m.issym() else None})
    write(private / "snapshot.json", {"source": str(source), "commit": actual, "archive_sha256": digest(archive),
          "tree_sha256": tree_hash(target), "policy": policy, "tokens": tokens, "dependency_tokens_in_pom_only": dependency_tokens, "files": entries,
          "full_paper_anonymization": False,
          "limitations": "Line-preserving reconstruction; package paths, short names, binaries and semantic identity may remain. Not an author-provided anonymized dataset."})
    return redactor
