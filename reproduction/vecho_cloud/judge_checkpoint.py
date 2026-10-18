"""Reuse saved judge successes and run only records still missing a result."""
import json
import copy
from collections import Counter
from vecho_judge.app.service import normalize_file, add_usage
from vecho_judge.memory_client import MemoryClient
from vecho_judge.outputs import RunWriter
from vecho_judge.runtime import JudgeRuntimeConfig, run_llm_judge
from vecho_judge.schemas.types import JudgeResult, GuidanceRecord
from vecho_judge.outputs.writer import safe_name
from judge_identity import unique_records


def judge_checkpoint(report, source_type, cfg):
    original = normalize_file(report, source_type)
    raw_payload = copy.deepcopy([r.to_dict() for r in original])
    normalized = unique_records(original)
    payload = [r.to_dict() for r in normalized]
    previous, migrated = {}, []
    for path in sorted(cfg.state_dir.glob("*/inputs/normalized.json")):
        old_payload = json.loads(path.read_text())
        if old_payload == raw_payload and old_payload != payload:
            # Legacy writers overwrote inputs/results named by duplicate IDs.
            # Only the LAST input for such an ID has an identifiable saved
            # result, and only if the original summary reports no failed calls.
            directory = path.parents[1]
            summary = json.loads((directory / "summary.json").read_text())
            counts = Counter(r["fingerprint"] for r in raw_payload)
            last = {r["fingerprint"]: i for i, r in enumerate(raw_payload)}
            for i, (old_record, current) in enumerate(zip(raw_payload, normalized)):
                fp = old_record["fingerprint"]
                if counts[fp] > 1 and (i != last[fp] or summary["failures"] or
                                       summary["result_count"] != summary["normalized_count"]):
                    continue
                source_input = directory / "inputs" / (safe_name(fp) + ".json")
                source_result = directory / "results" / (safe_name(fp) + ".json")
                if not source_input.exists() or not source_result.exists():
                    continue
                if json.loads(source_input.read_text()) != old_record:
                    continue
                item = json.loads(source_result.read_text())
                if item.get("fingerprint") != fp or item.get("judge_metadata", {}).get("memory_errors"):
                    continue
                provenance = {"old_fingerprint": fp, "new_fingerprint": current.fingerprint,
                              "source_input": str(source_input), "source_result": str(source_result)}
                item["fingerprint"] = current.fingerprint
                item["judge_metadata"] = {**item.get("judge_metadata", {}), "identity_migration": provenance}
                previous[current.fingerprint] = item
                migrated.append(provenance)
            continue
        if old_payload != payload:
            raise RuntimeError("Checkpoint inputs differ from current scan report")
        for result_path in sorted((path.parents[1] / "results").glob("*.json")):
            item = json.loads(result_path.read_text())
            if result_path.name != safe_name(item["fingerprint"]) + ".json":
                raise RuntimeError("Saved judge result identity differs from its input filename")
            if not item.get("judge_metadata", {}).get("memory_errors"):
                previous[item["fingerprint"]] = item
    writer = RunWriter(cfg.state_dir)
    directory = writer.start_run()
    writer.write_normalized_inputs(directory, normalized)
    results, guidance, failures, usage = [], [], [], {}
    reused = []
    for record in normalized:
        if record.fingerprint in previous:
            result = JudgeResult(**previous[record.fingerprint])
            guide = GuidanceRecord(result.fingerprint, "vecho_judge", result.re_scan_guidance, ["judge_status_" + result.vuln_status], cfg.project_name)
            writer.write_record_output(directory, record, result, guide, [], [], result.usage)
            reused.append(record.fingerprint)
        else:
            memory = MemoryClient(enabled=cfg.memory.enabled, url=cfg.memory.url, project=cfg.memory.project, timeout_seconds=cfg.memory.timeout_seconds, errors=[])
            runtime = JudgeRuntimeConfig(repo_root=cfg.repo_root, model=cfg.model, base_url=cfg.base_url, api_key=cfg.api_key, prompt_path=cfg.prompt_path, max_turns=cfg.max_turns, project_name=cfg.project_name, memory=memory)
            try:
                output = run_llm_judge(record, runtime)
                if output.result.fingerprint != record.fingerprint:
                    raise RuntimeError("Judge returned a different record identity")
                if output.result.judge_metadata.get("memory_errors"):
                    raise RuntimeError("Memory errors during judge")
                result, guide = output.result, output.guidance
                writer.write_record_output(directory, record, result, guide, output.transcript, output.tool_calls, output.usage)
            except Exception as exc:
                failures.append({"fingerprint": record.fingerprint, "error": str(exc)})
                continue
        results.append(result)
        guidance.append(guide)
        add_usage(usage, result.usage)
    writer.write_guidance_index(directory, guidance)
    writer.write_summary(directory, normalized, results, guidance, usage, failures)
    writer.write_rescan_bundle(directory, cfg.project_name, str(cfg.repo_root), normalized, results, guidance)
    (directory / "checkpoint.json").write_text(json.dumps({"identity_version": 2, "reused_fingerprints": reused, "identity_migrations": migrated, "note": "Reused output transcripts remain in earlier runs; aggregate usage includes reused records and must not be added across attempts"}, indent=2))
    return directory, normalized, results, guidance
