package contextaudit

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"vecho_final/scaner/internal/model"
)

func systemPrompt() string {
	return `You are vEcho Flow Verification, the stage that extends one seed into an evidence-backed propagation chain.
Your job is not to search for new seeds. Stay centered on the current case and trace upstream/downstream across the whole repo when needed.

Rules:
- Use FindJavaSymbol/Read/Grep/Glob/Bash to inspect code before adding chain steps or facts.
- Add only source, propagation, sink, sanitizer, or guard steps.
- Keep the chain ordered from source toward sink. If starting from a sink, prepend upstream steps. If starting from a source, append downstream steps.
- If starting from a sanitizer or guard, verify its real semantics in context; a check-looking function is not proof of safety.
- When a sanitizer, guard, sandbox, authorization, or allowlist step is relevant, add a sanitizer_result or guard_condition fact with content.effect = "blocks", "bypassed", "not_dominating", "not_applicable", or "unknown".
- If the case starts from sanitizer/control_point, or the current chain contains a sanitizer/guard, do not claim confirmed until you have evidenced effect="bypassed", "not_dominating", or "not_applicable" for that check.
- If starting from a propagation hop, expand both upstream and downstream until one side is proven or blocked.
- Every step and fact you add must include proof with file and line from code that has been read in this case.
- Seed rationale, titles, and propagation hints are hypotheses, not proof. Use them to choose what to read, not as evidence.
- If sanitizer or guard truly blocks the tracked value before the sink, return dead_end or rejected, not confirmed.
- Return confirmed only when the chain contains a code-evidenced source and sink in order.
- Do not assume or target external answer keys, external vulnerability writeups, vulnerability IDs, patch artifacts, or known fixes. Use only target-repo code evidence plus generic security knowledge.
- Return only JSON. No markdown.

Library analysis policy (explicit improvement variant):
- This target may be a reusable library. Missing production callers, only test usages, or an absent browser/eval sink in this repository do NOT establish safety. Mark this limitation blocked, not dead_end/rejected.
- A public API parameter may be a caller-supplied source, and an unsafe return/guard/encoding contract may be a library boundary sink ONLY when the read API contract and implementation support that interpretation. State the assumed consumer/output context; do not invent an external application or call edge. If that contract cannot be established, retain blocked.
- A sanitizer name, documentation, or call such as s.sanitize() is NOT proof that dangerous input is blocked. Inspect implementation, possible bypasses and actual output context before claiming blocks.
- For effect=blocks, content must include reason, constraint, output_context, and implementation_evidence: [{"file":"...","line":1,"snippet":"actual read implementation branch or transformation"}]. Cite both the use site and actual implementation. The engine only validates evidence structure/read locations, not universal correctness.
- To find a method, first use FindJavaSymbol with its exact unqualified name and file_path, then Read at the returned declaration line. Navigate overloads and paginate instead of repeating broad Grep hits in comments.
- A truncated Read/Grep result is incomplete evidence. Continue at the next offset. Never infer implementation absence from the first page.

Generic vulnerability lenses:
- Path/resource traversal: file/resource names, archive entries, decoding/canonicalization/normalization order, path joins/resolution, stream/file reads, and weak string boundary checks.
- Command/code/expression injection: process execution, script/expression/template engines, dynamic class/method loading, plugin dispatch, and sandbox/allowlist boundaries.
- Archive/package extraction: uploaded or downloaded archives, package imports, archive entry names, unzip/extract helpers, path joins from entry names to destination directories, and file write/copy sinks.
- Constructor/reflection/sandbox boundaries: reflective construction, constructor selection, proxy/interceptor dispatch, sandbox hooks, allowlist/denylist checks, and permits/reject decisions around dynamic calls.
- XSS/output encoding: template/render/model flows, HTML/JS/CSS/URL contexts, escaping wrappers, and context-mismatched encoders.
- Query/template injection: query builders, ORM wrappers, dynamic filters/sorts, and string interpolation into query/template sinks.
- Deserialization/parser boundaries: object mappers, JSON/XML/YAML/binary parsers, polymorphic type handling, and parser config from runtime state.
- Authorization/workflow: ownership/role/permission checks, state transitions, approval gates, and guards that may not dominate the sink.

Action JSON schema:
{
  "thought": "brief reasoning",
  "tool_calls": [{"tool":"FindJavaSymbol|Read|Grep|Glob|Bash", "args": {}}],
  "prepend_steps": [{"kind":"source|propagation|sink|sanitizer|guard", "symbol":"...", "file":"relative/path", "line":1, "snippet":"...", "summary":"...", "relation_from_prev":"assign|arg_pass|return|field_flow|call|sanitize|guard", "proof":[{"file":"relative/path", "line":1, "snippet":"..."}]}],
  "append_steps": [{"kind":"source|propagation|sink|sanitizer|guard", "symbol":"...", "file":"relative/path", "line":1, "snippet":"...", "summary":"...", "relation_from_prev":"assign|arg_pass|return|field_flow|call|sanitize|guard", "proof":[{"file":"relative/path", "line":1, "snippet":"..."}]}],
  "facts": [{"type":"tracked_value|alias|transform|sanitizer_result|guard_condition|open_question", "content":{"effect":"blocks|bypassed|not_dominating|not_applicable|unknown optional for sanitizer_result/guard_condition"}, "file":"relative/path", "line":1, "snippet":"...", "proof":[{"file":"relative/path", "line":1, "snippet":"..."}]}],
  "next_question": "what to trace next",
  "case_status": {"status":"continue|confirmed|dead_end|blocked|rejected", "reason":"..."}
}

Tool argument schemas:
- FindJavaSymbol: {"file_path":"relative/File.java", "symbol":"exactMethodName", "offset":0}
- Read: {"file_path":"relative/path", "offset":1, "limit":200}
- Grep: {"pattern":"regex", "path":"relative/path optional", "glob":"**/*.java optional", "output_mode":"files_with_matches|content|count", "context":0, "head_limit":100, "type":"java|go|js|py optional"}
- Glob: {"pattern":"**/*.java", "path":"relative/path optional", "limit":100, "offset":0}
- Bash: {"command":"read-only shell command", "workdir":"relative/path optional", "timeout_ms":30000}`
}

func casePrompt(c Case, recent int) string {
	view := promptCaseView{
		CaseID:       c.CaseID,
		SeedID:       c.SeedID,
		SeedKind:     string(c.Seed.Kind),
		SeedTitle:    c.Seed.Title,
		SeedLocation: c.Seed.Location,
		Status:       c.Status,
		NextQuestion: c.NextQuestion,
		RecentSteps:  recentSteps(c.Steps, recent),
		Facts:        c.Facts,
		HasSource:    firstStep(c.Steps, StepSource) != nil,
		HasSink:      firstStep(c.Steps, StepSink) != nil,
	}
	data, _ := json.MarshalIndent(view, "", "  ")
	return fmt.Sprintf(`Current ContextAudit case:
%s

Continue from next_question. Use repo-wide tools when needed, but do not restart seed discovery. If you need more code, call tools. If you have enough inspected evidence, add prepend_steps/append_steps/facts and set case_status.`, data)
}

type promptCaseView struct {
	CaseID       string      `json:"case_id"`
	SeedID       string      `json:"seed_id"`
	SeedKind     string      `json:"seed_kind"`
	SeedTitle    string      `json:"seed_title"`
	SeedLocation any         `json:"seed_location"`
	Status       CaseStatus  `json:"status"`
	NextQuestion string      `json:"next_question,omitempty"`
	RecentSteps  []ChainStep `json:"recent_steps,omitempty"`
	Facts        []Fact      `json:"facts,omitempty"`
	HasSource    bool        `json:"has_source"`
	HasSink      bool        `json:"has_sink"`
}

func recentSteps(steps []ChainStep, n int) []ChainStep {
	if n <= 0 || len(steps) <= n {
		return append([]ChainStep(nil), steps...)
	}
	return append([]ChainStep(nil), steps[len(steps)-n:]...)
}

func parseAction(content string) (Action, error) {
	var action Action
	clean := extractJSON(content)
	if clean != "" {
		if err := json.Unmarshal([]byte(clean), &action); err == nil {
			if actionHasContent(action) {
				return action, nil
			}
		}
	}
	if toolCalls := parseTaggedToolCalls(content); len(toolCalls) > 0 {
		return Action{ToolCalls: toolCalls}, nil
	}
	return action, fmt.Errorf("no valid ContextAudit JSON action found in LLM response")
}

func actionHasContent(action Action) bool {
	return action.Thought != "" ||
		len(action.ToolCalls) > 0 ||
		len(action.PrependSteps) > 0 ||
		len(action.AppendSteps) > 0 ||
		len(action.Facts) > 0 ||
		action.NextQuestion != "" ||
		action.CaseStatus != nil
}

func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		lines := strings.Split(s, "\n")
		if len(lines) >= 3 {
			lines = lines[1 : len(lines)-1]
			s = strings.Join(lines, "\n")
		}
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end < start {
		return ""
	}
	return s[start : end+1]
}

var taggedToolCallPattern = regexp.MustCompile(`(?s)<\|tool_call_begin\|>\s*(?:functions\.)?([A-Za-z][A-Za-z0-9_]*)[^<]*<\|tool_call_argument_begin\|>\s*(\{.*?\})\s*<\|tool_call_end\|>`)

func parseTaggedToolCalls(content string) []model.ToolCallRequest {
	matches := taggedToolCallPattern.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return nil
	}
	var calls []model.ToolCallRequest
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(match[2]), &raw); err != nil {
			continue
		}
		calls = append(calls, model.ToolCallRequest{Tool: match[1], Args: raw})
	}
	return calls
}
