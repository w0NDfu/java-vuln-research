"""All unpublished choices are explicit, frozen, and hashed before execution."""
import copy
import math
import re
from pathlib import Path
from .io import read, digest

PIN = "68da10388878f8626f0a1d124e500c979ac1e82d"
DEFAULTS = {
    "schema_version": 1, "profile": "reconstruction", "artifact_commit": PIN,
    "samples": [1], "replicate": 1,
    "scanner": {"concurrency": 5, "turns_per_block": 8, "steps_per_case": 8,
                "turns_per_step": 6, "tools_per_case": 30, "timeout_seconds": 600},
    "judge": {"max_turns": 10, "final_save_adapter": False},
    "loop": {"max_rescans": 2, "patience": 1, "max_new_candidates": 1000},
    "memory": {"policy": "manual", "scope": "project", "seed": None},
    "anonymization": {"enabled": True, "tokens": [], "redact_dependency_coordinates": True},
    "static_sources": [], "require_static": True,
    "budget": {"limit_usd": 0, "opening_spend_usd": 0, "max_requests": 0},
    "assumptions": ["Unpublished historical sampling and termination settings are reconstructed.",
                    "This configuration is not a claim of exact paper reproduction."],
}


def merge(a, b):
    a = copy.deepcopy(a)
    for key, value in b.items():
        if key not in a:
            a[key] = copy.deepcopy(value)
        elif isinstance(a[key], dict) and isinstance(value, dict):
            a[key] = merge(a[key], value)
        else:
            a[key] = copy.deepcopy(value)
    return a


def load(path):
    path = Path(path).resolve()
    cfg = merge(DEFAULTS, read(path))
    for key in ["artifact", "dataset", "workspace"]:
        if not cfg.get(key):
            raise ValueError("Missing configuration: " + key)
        cfg[key] = str((path.parent / cfg[key]).resolve())
    if cfg.get("scanner_binary"):
        cfg["scanner_binary"] = str((path.parent / cfg["scanner_binary"]).resolve())
    if cfg["memory"]["seed"]:
        cfg["memory"]["seed"] = str((path.parent / cfg["memory"]["seed"]).resolve())
    cfg["config_dir"] = str(path.parent)
    validate(cfg)
    return cfg


def validate(cfg):
    if cfg["schema_version"] != 1 or cfg["artifact_commit"] != PIN:
        raise ValueError("Unsupported schema or artifact revision")
    if cfg["profile"] not in {"reconstruction", "enhanced", "ablation"}:
        raise ValueError("Unknown experiment profile")
    if not cfg["samples"] or len(set(cfg["samples"])) != len(cfg["samples"]) or any(type(i) is not int or i < 1 for i in cfg["samples"]):
        raise ValueError("samples must be an explicit ordered list of distinct positive IDs")
    for value in [cfg["replicate"], *cfg["scanner"].values(), cfg["judge"]["max_turns"],
                  cfg["loop"]["patience"], cfg["loop"]["max_new_candidates"]]:
        if type(value) is not int or value < 1:
            raise ValueError("Execution limits must be positive integers")
    if type(cfg["loop"]["max_rescans"]) is not int or cfg["loop"]["max_rescans"] < 0:
        raise ValueError("max_rescans must be non-negative")
    if cfg["memory"]["policy"] not in {"disabled", "manual", "auto_index", "frozen"}:
        raise ValueError("Unknown knowledge admission policy")
    if cfg["memory"]["scope"] not in {"project", "campaign"}:
        raise ValueError("Unknown knowledge scope")
    if len(cfg["models"]) != 4 or set(cfg["models"]) != {"scan", "judge", "memory", "embedding"}:
        raise ValueError("Declare scan/judge/memory/embedding models")
    from urllib.parse import urlsplit
    for role, m in cfg["models"].items():
        u = urlsplit(m["base_url"])
        if u.scheme not in {"http", "https"} or u.username or u.password or u.query or u.fragment:
            raise ValueError("Provider base URL must not contain credentials/query parameters")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", m["key_env"]):
            raise ValueError("Credentials must be environment variable names")
        for key in ["input_usd_per_million", "output_usd_per_million"]:
            if isinstance(m[key], bool) or not math.isfinite(m[key]) or m[key] < 0:
                raise ValueError("Explicit non-negative prices are required")
        if type(m["context_tokens"]) is not int or m["context_tokens"] < 1:
            raise ValueError("context_tokens required")
        if role != "embedding" and (type(m["max_output_tokens"]) is not int or not 0 < m["max_output_tokens"] < m["context_tokens"]):
            raise ValueError("Explicit output token limit must be less than context capacity")
        if role != "embedding" and not isinstance(m.get("sampling"), dict):
            raise ValueError("Declare sampling explicitly, including an empty object if using provider defaults")
        if set(m.get("sampling", {})) - {"temperature", "top_p", "seed", "presence_penalty", "frequency_penalty"}:
            raise ValueError("Unsupported sampling option")
        for key, value in m.get("sampling", {}).items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError("Sampling values must be finite numbers")
            if key == "seed" and type(value) is not int: raise ValueError("Sampling seed must be an integer")
            if key == "temperature" and not 0 <= value <= 2: raise ValueError("Temperature out of range")
            if key == "top_p" and not 0 < value <= 1: raise ValueError("top_p out of range")
    for key in ["limit_usd", "opening_spend_usd"]:
        v = cfg["budget"][key]
        if isinstance(v, bool) or not math.isfinite(v) or v < 0:
            raise ValueError("Invalid budget")
    if type(cfg["budget"]["max_requests"]) is not int or cfg["budget"]["max_requests"] < 0:
        raise ValueError("Invalid request limit")
    for source in cfg["static_sources"]:
        if not source.get("path"): raise ValueError("Static report path required")
        if source["format"] not in {"sarif", "coverity-json", "canonical"}:
            raise ValueError("Unsupported static report format")
        if not source.get("tool") or not source.get("version") or not source.get("queries"):
            raise ValueError("Static producer version and query policy must be declared")
        for command in source.get("commands", []):
            if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
                raise ValueError("Static commands use argv arrays; shell strings are not supported")
    if cfg["require_static"] and not cfg["static_sources"]:
        raise ValueError("Full reconstruction requires declared static sources; use explicit ablation to omit them")
    if not cfg["require_static"] and cfg["profile"] == "reconstruction":
        raise ValueError("Missing static inputs must be labelled ablation or enhanced")


def identity(cfg):
    return digest(cfg)
