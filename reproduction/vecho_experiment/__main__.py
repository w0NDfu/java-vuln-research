import argparse
import json
import sys
from pathlib import Path
from .config import load
from .io import read, write


def main(argv=None):
    parser = argparse.ArgumentParser(description="vEcho method reconstruction; no live calls without run --execute")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ["plan", "preflight", "prepare", "run", "status", "stop"]:
        p = sub.add_parser(name); p.add_argument("--config", required=True, type=Path)
        if name == "run":
            p.add_argument("--execute", action="store_true"); p.add_argument("--resume", action="store_true")
    p = sub.add_parser("compare"); p.add_argument("--left", type=Path, required=True); p.add_argument("--right", type=Path, required=True); p.add_argument("--out", type=Path)
    p = sub.add_parser("approve", help="Record offline SHA256 review; index on next explicitly executed run")
    p.add_argument("--config", required=True, type=Path); p.add_argument("--sample", required=True, type=int)
    p.add_argument("--document", required=True); p.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    if args.command == "compare":
        from .evaluation import compare
        result = compare(args.left, args.right)
        if args.out: write(args.out, result)
    else:
        cfg = load(args.config)
        if args.command == "preflight":
            from .preflight import check
            result = check(cfg)
        elif args.command == "approve":
            from .io import inside, file_hash, now
            if cfg["memory"]["policy"] != "manual" or args.sample not in cfg["samples"]: raise ValueError("Manual review requires a configured sample and manual policy")
            sample = f"sample_{args.sample:04d}"
            directory = Path(cfg["workspace"]) / "knowledge" / ("campaign" if cfg["memory"]["scope"] == "campaign" else sample)
            if args.document.replace("\\", "/").split("/")[0] not in {"common", sample}: raise ValueError("Wrong knowledge project")
            path = inside(directory / "kb_tmp", args.document)
            if file_hash(path) != args.sha256: raise ValueError("Reviewed document hash mismatch")
            decisions = directory / "review-decisions.json"
            result = read(decisions) if decisions.exists() else {}
            result[args.document] = {"sha256": args.sha256, "reviewed_at": now()}
            write(decisions, result)
            result = {"approved": args.document, "indexed": False, "model_requests_started": False}
        elif args.command == "prepare":
            from .runtime import prepare
            result = prepare(cfg)
        elif args.command == "run" and args.execute:
            from .runner import run
            result = run(cfg, args.resume)
        elif args.command == "status":
            root = Path(cfg["workspace"])
            result = {"experiment": read(root / "experiment.json") if (root / "experiment.json").exists() else None,
                      "summary": read(root / "summary.json") if (root / "summary.json").exists() else None}
        elif args.command == "stop":
            root = Path(cfg["workspace"])
            if not (root / "experiment.json").exists(): raise ValueError("No experiment at this workspace")
            (root / "STOP").write_text("Stop requested by operator\n", encoding="utf-8")
            result = {"stop_requested": True, "note": "New model calls denied; in-flight calls may finish before worker shutdown."}
        else:
            from .runner import plan
            result = plan(cfg)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.command == "run" and args.execute and not result.get("all_workflows_complete"):
        return 1
    if args.command == "preflight" and not result["ready"]: return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        print(type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        raise SystemExit(2)
