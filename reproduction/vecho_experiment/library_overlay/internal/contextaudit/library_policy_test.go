package contextaudit

import (
	"encoding/json"
	"strings"
	"testing"
	"vecho_final/scaner/internal/model"
	"vecho_final/scaner/internal/tools"
)

func TestLibraryMissingCallerIsUnresolvedNotSafe(t *testing.T) {
	for _, reason := range []string{"Only used in tests", "not used in production code", "No call sites pass attacker-controlled data", "There is no evidence of downstream file operation sinks"} {
		c := Case{}
		r := evaluate(&c, &StatusUpdate{Status: "dead_end", Reason: reason}, false)
		if r.Status != StatusBlocked {
			t.Fatalf("unsafe dismissal %q: %+v", reason, r)
		}
	}
}
func TestLibrarySanitizerCallIsNotBlockingProof(t *testing.T) {
	lines := map[string]map[int]string{"A.java": {1: "s.sanitize();", 2: "if (value.indexOf('<') >= 0) throw new IllegalArgumentException();"}}
	for _, test := range []struct {
		name  string
		proof string
		valid bool
	}{
		{"no implementation", "", false},
		{"unread implementation", `[{"file":"A.java","line":9,"snippet":"if (safe) {}"}]`, false},
		{"call only", `[{"file":"A.java","line":1,"snippet":"s.sanitize();"}]`, false},
		{"read constraint", `[{"file":"A.java","line":2,"snippet":"if (value.indexOf('<') >= 0) throw new IllegalArgumentException();"}]`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			content := map[string]any{"effect": "blocks", "blocking_evidence_checked": true, "constraint": "reject literal < before return", "output_context": "specific literal-delimiter contract", "reason": "guard dominates this return"}
			if test.proof != "" {
				var p any
				_ = json.Unmarshal([]byte(test.proof), &p)
				content["implementation_evidence"] = p
			}
			f, err := factFromDraft(&Case{}, FactDraft{Type: "sanitizer_result", Content: content, File: "A.java", Line: 1}, lines)
			if err != nil {
				t.Fatal(err)
			}
			if f.Content["blocking_evidence_checked"] != test.valid {
				t.Fatalf("unexpected validation: %+v", f)
			}
			c := Case{Facts: []Fact{f}}
			r := evaluate(&c, &StatusUpdate{Status: "dead_end", Reason: "sanitizer blocks"}, false)
			want := StatusBlocked
			if test.valid {
				want = StatusDeadEnd
			}
			if r.Status != want {
				t.Fatalf("got %s want %s", r.Status, want)
			}
		})
	}
}
func TestLibraryNavigationHintsPaginationAndRepeat(t *testing.T) {
	seen := map[string]int{}
	call := model.ToolCallRequest{Tool: "Read", Args: json.RawMessage(`{"file_path":"A.java","offset":1,"limit":200}`)}
	r := tools.ToolResult{Data: tools.ReadOutput{Offset: 1, LinesRead: 200, TotalLines: 700, Truncated: true}}
	if !strings.Contains(navigationHint(call, r, seen), "next offset=201") {
		t.Fatal("no pagination hint")
	}
	if !strings.Contains(navigationHint(call, r, seen), "FindJavaSymbol") {
		t.Fatal("no repeat hint")
	}
}
