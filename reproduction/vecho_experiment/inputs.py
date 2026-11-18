"""Preserve paths and provenance when converting static reports to vEcho JSON."""
import copy
import posixpath
import re
from urllib.parse import unquote, urlsplit
from .io import digest


def relative_path(value, source_root=""):
    value = unquote(str(value)).replace("\\", "/")
    if value.startswith("file:"):
        u = urlsplit(value)
        if u.netloc not in {"", "localhost"}:
            raise ValueError("Remote SARIF artifact is not a local source path")
        value = u.path
    if re.match(r"^/[A-Za-z]:/", value):
        value = value[1:]
    root = unquote(str(source_root)).replace("\\", "/").rstrip("/")
    if root.startswith("file:"):
        root = urlsplit(root).path.rstrip("/")
        if re.match(r"^/[A-Za-z]:/", root):
            root = root[1:]
    if root and (value.startswith(root + "/") or value.lower().startswith(root.lower() + "/") and re.match(r"^[A-Za-z]:", root)):
        value = value[len(root) + 1:]
    elif value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        # vEcho uses /src/... for repo-relative locations. Imported absolute
        # reports require explicit source-root mapping, never basename guessing.
        raise ValueError("Absolute report path needs a matching source_root: " + value)
    value = posixpath.normpath(value)
    if value in {"", ".", ".."} or value.startswith("../") or "\x00" in value:
        raise ValueError("Invalid source path")
    return value


def node(path, line, message="", source_root=""):
    if isinstance(line, bool) or int(line) < 1:
        raise ValueError("Invalid source line")
    return {"file_path": relative_path(path, source_root), "line_number": int(line), "description": message}


def record(tool, rule, message, locations, flows, origin):
    if not locations and not flows:
        raise ValueError("Finding has no source location")
    locations = locations or [flows[0][-1]]
    affected = {}
    for loc in locations:
        affected.setdefault(loc["file_path"], set()).add(loc["line_number"])
    return {"description": message, "short_description": rule, "category": rule,
            "source_scanner": tool, "cwe": "", "severity": "",
            "affected_files": [{"file_path": p, "line_numbers": sorted(lines)} for p, lines in sorted(affected.items())],
            "tainted_data_flow": flows,
            "metadata": {"origins": [origin], "path_evidence": "reported_path" if flows else "location_only"}}


def sarif(payload, tool, source_root=""):
    if payload.get("version") != "2.1.0":
        raise ValueError("Only SARIF 2.1.0 is supported")
    out = []
    for run_index, run in enumerate(payload["runs"]):
        if any(i.get("executionSuccessful") is False for i in run.get("invocations", [])):
            raise ValueError("SARIF producer reported failed execution")
        def artifact(a, seen=()):
            a = dict(a)
            if "uri" not in a and "index" in a:
                a = {**run["artifacts"][a["index"]]["location"], **a}
            uri = a.get("uri")
            if uri is None:
                raise ValueError("SARIF artifact has no URI")
            base = a.get("uriBaseId")
            if base and not urlsplit(uri).scheme and not uri.startswith("/"):
                if base in seen:
                    raise ValueError("Cyclic SARIF URI bases")
                target = run.get("originalUriBaseIds", {}).get(base)
                if target:
                    from urllib.parse import urljoin
                    uri = urljoin(artifact(target, seen + (base,)), uri)
                elif not source_root:
                    raise ValueError("Unresolved SARIF uriBaseId")
            return uri
        def location(loc):
            physical = loc["physicalLocation"]
            return node(artifact(physical["artifactLocation"]), physical["region"]["startLine"],
                        loc.get("message", {}).get("text", ""), source_root)
        for index, item in enumerate(run.get("results", [])):
            paths = []
            for flow in item.get("codeFlows", []):
                for thread in flow.get("threadFlows", []):
                    steps = []
                    for step in thread.get("locations", []):
                        if "index" in step:
                            step = {**run["threadFlowLocations"][step["index"]], **step}
                        steps.append(location(step["location"]))
                    if steps:
                        paths.append(steps)
            out.append(record(tool, item.get("ruleId", "unknown"), item.get("message", {}).get("text", ""),
                              [location(x) for x in item.get("locations", [])], paths,
                              {"tool": tool, "run": run_index, "index": index, "format": "sarif"}))
    return out


def coverity(payload, tool, source_root=""):
    """cov-format-errors --json-output-v7 shape; unknown export layouts fail."""
    if not isinstance(payload.get("issues"), list):
        raise ValueError("Expected Coverity JSON issues array; use SARIF/canonical for other export versions")
    out = []
    for index, item in enumerate(payload["issues"]):
        events = item.get("events", [])
        if not isinstance(events, list):
            raise ValueError("Invalid Coverity events")
        # Preserve diagnostic events; nested event traces form separate paths,
        # never silently reclassify an impact location as a proved taint chain.
        paths = []
        def trace(events):
            path = []
            for e in events:
                if e.get("filePathname") and e.get("lineNumber"):
                    path.append(node(e["filePathname"], e["lineNumber"], e.get("eventDescription", ""), source_root))
                if e.get("events"):
                    trace(e["events"])
            if path:
                paths.append(path)
        trace(events)
        main = [node(item["mainEventFilePathname"], item["mainEventLineNumber"], "", source_root)]
        r = record(tool, item["checkerName"], item.get("checkerProperties", {}).get("shortDescription", item["checkerName"]),
                   main, paths, {"tool": tool, "index": index, "format": "coverity-json", "mergeKey": item.get("mergeKey")})
        r["metadata"]["path_evidence"] = "diagnostic_event_trace" if paths else "location_only"
        out.append(r)
    return out


def canonical(payload, source_root="", vecho_paths=False):
    rows = payload if isinstance(payload, list) else payload["vulnerabilities"]
    out = copy.deepcopy(rows)
    if not isinstance(out, list):
        raise ValueError("Canonical report must contain a vulnerabilities list")
    for r in out:
        r.setdefault("tainted_data_flow", [])
        r.setdefault("metadata", {})
        for loc in r.get("affected_files", []):
            path = loc["file_path"].lstrip("/") if vecho_paths else loc["file_path"]
            loc["file_path"] = relative_path(path, source_root)
            if not loc.get("line_numbers") or any(type(i) is not int or i < 1 for i in loc["line_numbers"]):
                raise ValueError("Invalid canonical affected lines")
        for flow in r["tainted_data_flow"]:
            if not flow:
                raise ValueError("Empty flow cannot be scored as a path")
            for loc in flow:
                path = loc["file_path"].lstrip("/") if vecho_paths else loc["file_path"]
                loc["file_path"] = relative_path(path, source_root)
                if type(loc["line_number"]) is not int or loc["line_number"] < 1:
                    raise ValueError("Invalid canonical flow line")
        if not r.get("affected_files") and not r["tainted_data_flow"]:
            raise ValueError("Canonical finding has no locations")
    return out


def key(r):
    paths = sorted({tuple((n["file_path"], n["line_number"]) for n in p) for p in r.get("tainted_data_flow", [])})
    locations = sorted((x["file_path"], tuple(sorted(x["line_numbers"]))) for x in r.get("affected_files", []))
    # Exact path equality is required across tools; endpoint-only merging can
    # discard alternative flows. Location-only diagnostics retain their rule.
    family = r.get("cwe") or r.get("category", "")
    return digest({"paths": paths, "family": family} if paths else {"locations": locations, "rule": family})


def merge_records(records, exclude_tests=True):
    merged, excluded = {}, []
    for raw in records:
        r = copy.deepcopy(raw)
        evidence = [n["file_path"] for p in r.get("tainted_data_flow", []) for n in p]
        evidence += [x["file_path"] for x in r.get("affected_files", [])]
        if exclude_tests and evidence and all("/test/" in "/" + x or x.startswith("test/") for x in evidence):
            excluded.append({"key": key(r), "reason": "test_only"}); continue
        fp = key(r)
        r["fingerprint"] = fp
        meta = r.setdefault("metadata", {})
        meta.setdefault("origins", [{"tool": r.get("source_scanner", "unknown"), "original_fingerprint": raw.get("fingerprint")}])
        if fp in merged:
            old = merged[fp]
            old["metadata"]["origins"].extend(meta["origins"])
            old["metadata"].setdefault("alternative_claims", []).append({"description": r.get("description"), "category": r.get("category")})
        else:
            merged[fp] = r
    return [merged[k] for k in sorted(merged)], excluded
