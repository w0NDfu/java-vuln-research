"""Original RAG engine behind the artifact's simple tool HTTP protocol.

Working directories and knowledge are campaign-owned. No old services are
started/stopped and no history/labels are imported. Admission is explicit.
"""
import contextlib
import json
import re
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .io import digest, write, read, inside, file_hash, now


class Knowledge:
    def __init__(self, root, policy, engine=None, redactor=None):
        self.root, self.policy, self.engine, self.redactor = Path(root), policy, engine, redactor
        self.mutex = threading.RLock()
        self.root.mkdir(parents=True, exist_ok=True)

    def invoke(self, tool, a, project):
        if not re.fullmatch(r"sample_\d{4,}", project):
            raise ValueError("Invalid memory project")
        with self.mutex:
            if tool == "query_knowledge":
                result = self.engine.query(a["query"], project)
                if not result.get("success", True): raise RuntimeError("Knowledge query failed")
                if str(result.get("combined_answer", "")).startswith("Error generating answer:"):
                    raise RuntimeError("Knowledge synthesis failed")
                return json.dumps(result, ensure_ascii=False)
            if tool == "get_document":
                source = a.get("source", "kb")
                if source not in {"kb", "kb_tmp"}: raise ValueError("Unknown memory source")
                rel = a.get("file_path", a.get("path", ""))
                rel = rel.replace("\\", "/")
                if rel.startswith(source + "/"): rel = rel[len(source) + 1:]
                if rel.split("/")[0] not in {"common", project}: raise ValueError("Knowledge belongs to another project")
                return inside(self.root / source, rel).read_text(encoding="utf-8")
            if tool == "save_result":
                if a.get("vuln_status") not in {"yes", "no", "unknown"}: raise ValueError("Invalid memory verdict")
                write(self.root / "analysis_outputs" / project / (digest(a) + ".json"), a)
                return "result saved"
            if tool == "save_knowledge":
                target = "common" if a.get("type", "general") == "general" else project
                title, content = str(a.get("title", "")), str(a.get("content", ""))
                if self.redactor:
                    title, content = self.redactor.mask(title), self.redactor.mask(content)
                body = "# " + title.replace("\n", " ") + "\n\n" + content + "\n"
                rel = target + "/general/" + digest(body.encode()) + ".md"
                p = inside(self.root / "kb_tmp", rel); p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(body, encoding="utf-8")
                if self.policy == "auto_index":
                    self.promote(rel, "configured_auto_index")
                    return "knowledge saved and indexed"
                return "knowledge staged; not in retrieval index"
            raise ValueError("Unknown memory tool")

    def promote(self, relative, decision):
        with self.mutex:
            src = inside(self.root / "kb_tmp", relative)
            dst = inside(self.root / "kb", relative)
            content = src.read_bytes()
            if dst.exists() and dst.read_bytes() != content: raise ValueError("Knowledge identity collision")
            dst.parent.mkdir(parents=True, exist_ok=True); dst.write_bytes(content)
            project = Path(relative).parts[0]
            if not self.engine.update_knowledge_base(project):
                raise RuntimeError("Knowledge indexing failed; no successful admission receipt")
            write(self.root / "admissions" / (digest(relative) + ".json"),
                  {"relative": relative, "sha256": file_hash(dst), "decision": decision, "at": now()})


@contextlib.contextmanager
def serve(cfg, directory, gateway_url, gateway_token, project, redactor=None, engine_factory=None):
    if cfg["memory"]["policy"] == "disabled":
        yield ""; return
    import yaml
    directory = Path(directory); directory.mkdir(parents=True, exist_ok=True)
    marker = directory / "seed.json"
    if not marker.exists():
        seed = cfg["memory"]["seed"]
        if seed:
            seed = Path(seed)
            if any(p.is_symlink() for p in seed.rglob("*")): raise ValueError("Knowledge seed links are unsupported")
            shutil.copytree(seed, directory / "kb", dirs_exist_ok=False)
        else:
            (directory / "kb/common").mkdir(parents=True, exist_ok=True)
        write(marker, {"seed": str(seed) if seed else None, "initial_knowledge": "operator supplied" if seed else "empty"})
    artifact = Path(cfg["artifact"])
    settings = yaml.safe_load((artifact / "memory/config.example.yaml").read_text(encoding="utf-8"))
    settings["knowledge_base"].update(base_path=str(directory / "kb"), common_path=str(directory / "kb/common"), project_prefix=str(directory / "kb") + "/")
    settings["rag"]["vector_store"]["persist_directory"] = str(directory / "chroma")
    for role, section in [("memory", "llm"), ("embedding", "embedding")]:
        settings["rag"][section].update(model=cfg["models"][role]["model"], api_key=gateway_token,
                                        api_base=gateway_url + "/" + role + "/v1")
    settings["save_tools"] = {"use_tmp": True}
    config_path = directory / "config.yaml"
    config_path.write_text(yaml.safe_dump(settings), encoding="utf-8"); config_path.chmod(0o600)
    if engine_factory is None:
        sys.path.insert(0, str(artifact / "memory"))
        from core.rag_engine import RAGEngine
        engine_factory = RAGEngine
    engine = engine_factory(str(config_path))
    kb = Knowledge(directory, cfg["memory"]["policy"], engine, redactor)
    decisions = directory / "review-decisions.json"
    if cfg["memory"]["policy"] == "manual" and decisions.exists():
        for relative, decision in read(decisions).items():
            src = inside(directory / "kb_tmp", relative)
            if file_hash(src) != decision["sha256"]: raise ValueError("Approved knowledge changed after review")
            receipt = directory / "admissions" / (digest(relative) + ".json")
            if not receipt.exists(): kb.promote(relative, "manual_sha256_review")
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            try:
                if self.path != "/invoke" or self.headers.get("project") != project: raise ValueError("Wrong memory route/project")
                n = int(self.headers.get("Content-Length", 0))
                if not 0 < n <= 1048576: raise ValueError("Invalid body")
                data = json.loads(self.rfile.read(n))
                response = {"ok": True, "content": kb.invoke(data["tool"], data.get("arguments", {}), project)}
                status = 200
            except Exception:
                response, status = {"ok": False, "error": "Knowledge operation failed"}, 502
            body = json.dumps(response).encode(); self.send_response(status)
            self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = False
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/invoke"
    finally:
        server.shutdown(); server.server_close(); thread.join()
