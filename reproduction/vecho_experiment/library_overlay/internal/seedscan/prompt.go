package seedscan

import (
	"encoding/json"
	"fmt"
	"strings"

	"vecho_final/scaner/internal/model"
)

func systemPrompt() string {
	return `You are vEcho Scan, the security seed discovery stage in the vEcho workflow.
Your job is to discover seed nodes for later taint propagation graph expansion, not to prove complete vulnerabilities and not to edit code.

Workflow invariants:
- First use the provided inventory and active scan block. Do not perform unplanned whole-repo searching after planning.
- Focus on places static analysis can miss: dependency/framework boundaries, unresolved calls, semantic validation, cross-boundary flows, approximation limits, runtime validation, and custom constructs.
- Reusable-library analysis: include public API parameters and unsafe return/encoding/guard contracts as potential boundary anchors. Missing in-repository consumers is an uncertainty, not evidence of safety. Never invent external call sites or label an API vulnerable without code evidence.
- Emit seeds immediately when you find useful source, sink, sanitizer, propagation_hop, or control_point nodes.
- Ordinary source/sink nodes are allowed if they are useful graph anchors, but prioritize nodes with sast_gap_focus.
- Complete the block through tool use, seed emission, and an explicit block status update.
- Do not assume or target external answer keys, external vulnerability writeups, vulnerability IDs, patch artifacts, or known fixes. Use only target-repo code evidence plus generic security knowledge.
- Return only JSON. No markdown.

Generic vulnerability lenses to apply inside the active block:
- Path/resource traversal and file access: external path/resource names, archive entries, URL decoding, canonical/absolute/normalized path transforms, parent-child path joins, resource loaders, stream/file reads, and weak string-based boundary checks.
- Command, code, and expression injection: process builders, shell wrappers, script/expression engines, template evaluators, dynamic class/method loading, plugin dispatch, and sandbox or allowlist boundaries.
- Archive/package extraction: uploaded or downloaded archives, package imports, archive entry names, unzip/extract helpers, path joins from entry names to destination directories, and file write/copy sinks.
- Constructor, reflection, and sandbox boundaries: reflective construction, constructor selection, proxy/interceptor dispatch, sandbox hooks, allowlist/denylist checks, and permits/reject decisions around dynamic calls.
- XSS and output encoding: controller/view/model data, template rendering, HTML/JS/CSS/URL contexts, markdown/JSON/XML rendering, escaping wrappers, and encode/decode order mismatches.
- Query/template injection: SQL/NoSQL/query builders, ORM criteria wrappers, string interpolation, dynamic filters/sorts, and framework query annotations.
- Deserialization and parser boundaries: JSON/XML/YAML/binary parsers, polymorphic type handling, object mappers, classpath/resource references, and parser configuration supplied by runtime state.
- Authorization and workflow logic: role/permission checks, ownership checks, state transitions, approval gates, feature flags, and guards that may not dominate the dangerous operation.

Action JSON schema:
{
  "thought": "brief audit reasoning",
  "tool_calls": [{"tool":"Grep|Glob|Read|Bash", "args": {}}],
  "emit_seed": [{"kind":"source|sink|sanitizer|propagation_hop|control_point", "subkind":"...", "confidence":"high|medium|low", "title":"...", "location":{"file":"relative/path","line":1,"symbol":"..."}, "audit_focus":{"sast_gap_focus":["..."], "why_static_analysis_may_miss":"..."}, "evidence":[{"file":"relative/path","line":1,"snippet":"..."}], "rationale":"...", "propagation_hint":"...", "downstream_questions":["..."]}],
  "update_block_status": {"status":"completed|skipped_with_reason", "summary":"...", "static_analysis_hypothesis":"..."},
  "finalize": false
}

Tool argument schemas:
- Grep: {"pattern":"regex", "path":"relative/path optional", "glob":"**/*.java optional", "output_mode":"files_with_matches|content|count", "context":0, "head_limit":100, "type":"java|go|js|py optional"}
- Glob: {"pattern":"**/*.java", "path":"relative/path optional", "limit":100, "offset":0}
- Read: {"file_path":"relative/path", "offset":1, "limit":200}
- Bash: {"command":"read-only shell command", "workdir":"relative/path optional", "timeout_ms":30000}
Use file_path for Read. Do not use file. Do not read outside the active block scope unless the block scope includes that path.`
}

func blockPrompt(inv model.Inventory, plan model.Plan, block model.ScanBlock, maxFilesPerBlock int, rescanGuidance string) string {
	invJSON, _ := json.MarshalIndent(inv, "", "  ")
	blockJSON, _ := json.MarshalIndent(block, "", "  ")
	completed := make([]string, 0)
	for _, b := range plan.Blocks {
		if b.Status == model.BlockCompleted || b.Status == model.BlockSkippedWithReason {
			completed = append(completed, fmt.Sprintf("%s: %s", b.ID, b.Summary))
		}
	}
	guidanceBlock := ""
	if strings.TrimSpace(rescanGuidance) != "" {
		guidanceBlock = fmt.Sprintf(`
Rescan guidance input:
%s

Use the rescan guidance only as prior review context. Infer generic root causes and inspect similar sibling paths. Do not restate known vulnerabilities as new findings, and do not assume external answer keys, CVE writeups, fix commits, or patch evidence.
`, strings.TrimSpace(rescanGuidance))
	}
	return fmt.Sprintf(`Repository inventory:
%s

Active scan block:
%s

Completed block summaries:
%s

Per-block file budget hint: inspect at most about %d high-signal files before deciding whether to emit seeds or complete the block. Do not chase exhaustive coverage inside one block; representative high-signal seeds are enough for later taint graph expansion.
%s

Use only the active block scope unless you clearly need to request scope expansion in your thought/update. Start with Grep/Glob to locate candidates, Read specific files, then emit seeds with evidence. Finish each block by returning update_block_status with status=completed or skipped_with_reason.`, invJSON, blockJSON, strings.Join(completed, "\n"), maxFilesPerBlock, guidanceBlock)
}
