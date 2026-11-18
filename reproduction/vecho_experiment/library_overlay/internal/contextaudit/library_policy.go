package contextaudit

// This variant checks evidence structure, not the truth of arbitrary LLM
// claims. It never turns a missing caller or a sanitizer name into a proof.
import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"vecho_final/scaner/internal/model"
	"vecho_final/scaner/internal/tools"
)

var missingCallerReason = regexp.MustCompile(`(?i)(only.{0,40}test|not used in.{0,30}(production|main|application)|no.{0,30}(production usage|call sites|downstream.{0,20}(usage|sink)|attacker.controlled (source|input))|not called.{0,30}production)`)

func libraryDisposition(c *Case, proposed *StatusUpdate, closure effectClosure) *StatusUpdate {
	if proposed == nil {
		return nil
	}
	if proposed.Status != "dead_end" && proposed.Status != "rejected" {
		return proposed
	}
	if missingCallerReason.MatchString(proposed.Reason) {
		return &StatusUpdate{Status: "blocked", Reason: "Library caller boundary unresolved; absence of repository callers does not establish safety: " + proposed.Reason}
	}
	if closure.Required && !closure.Closed && !closure.Blocking {
		return &StatusUpdate{Status: "blocked", Reason: "Guard/sanitizer safety remains unverified: " + proposed.Reason}
	}
	return proposed
}

// Require read implementation evidence as well as the use site and a specific
// constraint/output-context explanation. Mere call sites and comments fail.
func checkBlockingEvidence(d FactDraft, lines map[string]map[int]string) map[string]any {
	content := make(map[string]any)
	for k, v := range d.Content {
		content[k] = v
	}
	delete(content, "blocking_evidence_checked") // Never accept a model-supplied flag.
	if normalizeEffect(content["effect"]) != "blocks" {
		return content
	}
	content["blocking_evidence_checked"] = false
	for _, k := range []string{"constraint", "output_context", "reason"} {
		if value, ok := content[k].(string); !ok || strings.TrimSpace(value) == "" {
			return content
		}
	}
	proofs, ok := content["implementation_evidence"].([]any)
	if !ok || len(proofs) == 0 || len(proofs) > 16 {
		return content
	}
	implementation := false
	for _, item := range proofs {
		p, ok := item.(map[string]any)
		if !ok {
			return content
		}
		file, fok := p["file"].(string)
		snippet, sok := p["snippet"].(string)
		line, lok := p["line"].(float64)
		if !fok || !sok || !lok || line < 1 || line != float64(int(line)) || strings.TrimSpace(snippet) == "" {
			return content
		}
		resolved, err := resolveProof(Proof{File: file, Line: int(line), Snippet: snippet}, "", 0, "", lines)
		if err != nil {
			return content
		}
		s := strings.TrimSpace(resolved.Snippet)
		if strings.HasPrefix(s, "//") || strings.HasPrefix(s, "*") || strings.HasPrefix(s, "/*") {
			continue
		}
		// Navigation evidence must include actual branching/transformation rather
		// than a wrapper call such as s.sanitize(). This is a minimum, not a proof
		// of universal safety; the declared constraint remains in the receipt.
		if strings.Contains(s, "if (") || strings.Contains(s, "if(") || strings.HasPrefix(s, "case ") ||
			strings.HasPrefix(s, "throw ") || strings.Contains(s, ".replace(") || strings.Contains(s, ".replaceAll(") {
			implementation = true
		}
	}
	content["blocking_evidence_checked"] = implementation
	return content
}

func navigationHint(call model.ToolCallRequest, result tools.ToolResult, seen map[string]int) string {
	var args any
	_ = json.Unmarshal(call.Args, &args)
	canonical, _ := json.Marshal(args)
	key := strings.ToLower(call.Tool) + ":" + string(canonical)
	seen[key]++
	hint := ""
	if seen[key] > 1 {
		hint = "Repeated identical navigation request. Do not repeat it again. Use FindJavaSymbol for an exact method name, then Read at its returned line, or advance Grep offset."
	}
	if out, ok := result.Data.(tools.ReadOutput); ok && out.Truncated {
		hint += fmt.Sprintf(" Read has more lines: next offset=%d, total_lines=%d. The first page is not the full implementation.", out.Offset+out.LinesRead, out.TotalLines)
	}
	if out, ok := result.Data.(tools.GrepOutput); ok && result.Truncated {
		hint += fmt.Sprintf(" Grep was truncated: advance offset beyond %d or use FindJavaSymbol; missing results on this page are not absence evidence.", out.AppliedOffset+out.AppliedLimit)
	}
	return hint
}
