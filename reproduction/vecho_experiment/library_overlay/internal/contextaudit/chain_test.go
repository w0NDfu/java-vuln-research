package contextaudit

import (
	"testing"

	"vecho_final/scaner/internal/model"
)

func TestApplyDraftsAndEvaluateConfirmedChain(t *testing.T) {
	seed := model.Seed{ID: "seed-1", Kind: model.SeedSource, Title: "source", Location: model.Location{File: "A.java", Line: 1, Symbol: "cmd"}, Rationale: "request param"}
	c := newCase(1, seed)
	lines := map[string]map[int]string{"A.java": {1: "String cmd = request.getParameter(\"cmd\");", 2: "Runtime.getRuntime().exec(cmd);"}}
	insertEntryStep(&c, lines["A.java"][1])
	if err := applyDrafts(&c, nil, []StepDraft{{Kind: StepSink, Symbol: "exec", File: "A.java", Line: 2, Snippet: lines["A.java"][2], RelationFromPrev: "arg_pass", Proof: []Proof{{File: "A.java", Line: 2, Snippet: lines["A.java"][2]}}}}, nil, lines); err != nil {
		t.Fatal(err)
	}
	result := evaluate(&c, &StatusUpdate{Status: "confirmed"}, false)
	if result.Status != StatusConfirmed {
		t.Fatalf("status=%s, want confirmed: %+v", result.Status, result)
	}
}

func TestApplyDraftsRejectsUnreadProofLine(t *testing.T) {
	seed := model.Seed{ID: "seed-1", Kind: model.SeedSource, Location: model.Location{File: "A.java", Line: 1}}
	c := newCase(1, seed)
	lines := map[string]map[int]string{"A.java": {1: "source();"}}
	insertEntryStep(&c, lines["A.java"][1])
	err := applyDrafts(&c, nil, []StepDraft{{Kind: StepSink, File: "A.java", Line: 99, Proof: []Proof{{File: "A.java", Line: 99}}}}, nil, lines)
	if err == nil {
		t.Fatal("expected unread proof line to be rejected")
	}
}

func TestBlockingFactPreventsConfirmed(t *testing.T) {
	seed := model.Seed{ID: "seed-1", Kind: model.SeedSource, Location: model.Location{File: "A.java", Line: 1}}
	c := newCase(1, seed)
	lines := map[string]map[int]string{"A.java": {1: "source();", 2: "safe(cmd);", 3: "sink(cmd);"}}
	insertEntryStep(&c, lines["A.java"][1])
	if err := applyDrafts(&c, nil, []StepDraft{{Kind: StepSink, File: "A.java", Line: 3, Proof: []Proof{{File: "A.java", Line: 3}}}}, []FactDraft{{Type: "sanitizer_result", Content: map[string]any{"effect": "blocks"}, File: "A.java", Line: 2, Proof: []Proof{{File: "A.java", Line: 2}}}}, lines); err != nil {
		t.Fatal(err)
	}
	result := evaluate(&c, &StatusUpdate{Status: "confirmed"}, false)
	if result.Status != StatusBlocked {
		t.Fatalf("unverified sanitizer call must remain blocked, got %+v", result)
	}
}

func TestProofLineCorrectionWithinReadWindow(t *testing.T) {
	seed := model.Seed{ID: "seed-1", Kind: model.SeedSource, Location: model.Location{File: "A.java", Line: 1}}
	c := newCase(1, seed)
	lines := map[string]map[int]string{"A.java": {1: "source();", 2: "sink(cmd);"}}
	insertEntryStep(&c, lines["A.java"][1])
	err := applyDrafts(&c, nil, []StepDraft{{
		Kind:    StepSink,
		File:    "A.java",
		Line:    1,
		Snippet: lines["A.java"][2],
		Proof:   []Proof{{File: "A.java", Line: 1, Snippet: lines["A.java"][2]}},
	}}, nil, lines)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Steps[1].Line; got != 2 {
		t.Fatalf("corrected line=%d, want 2", got)
	}
}

func TestApplyDraftsKeepsValidItemsWhenOneProofFails(t *testing.T) {
	seed := model.Seed{ID: "seed-1", Kind: model.SeedSource, Location: model.Location{File: "A.java", Line: 1}}
	c := newCase(1, seed)
	lines := map[string]map[int]string{"A.java": {1: "source();", 2: "sink(cmd);"}}
	insertEntryStep(&c, lines["A.java"][1])
	err := applyDrafts(&c, nil, []StepDraft{
		{Kind: StepSink, File: "A.java", Line: 2, Proof: []Proof{{File: "A.java", Line: 2}}},
		{Kind: StepPropagation, File: "A.java", Line: 99, Proof: []Proof{{File: "A.java", Line: 99}}},
	}, nil, lines)
	if err == nil {
		t.Fatal("expected partial apply error")
	}
	applyErr, ok := err.(*draftApplyError)
	if !ok || !applyErr.HasApplied() {
		t.Fatalf("expected partial apply error, got %T %v", err, err)
	}
	if len(c.Steps) != 2 || c.Steps[1].Kind != StepSink {
		t.Fatalf("valid sink step was not retained: %+v", c.Steps)
	}
}

func TestGuardEffectMustBeExplicitBeforeConfirmation(t *testing.T) {
	seed := model.Seed{ID: "seed-1", Kind: model.SeedSource, Location: model.Location{File: "A.java", Line: 1}}
	c := newCase(1, seed)
	lines := map[string]map[int]string{"A.java": {1: "source();", 2: "if (allowed(cmd)) {}", 3: "sink(cmd);"}}
	insertEntryStep(&c, lines["A.java"][1])
	err := applyDrafts(&c, nil, []StepDraft{
		{Kind: StepGuard, File: "A.java", Line: 2, Proof: []Proof{{File: "A.java", Line: 2}}},
		{Kind: StepSink, File: "A.java", Line: 3, Proof: []Proof{{File: "A.java", Line: 3}}},
	}, nil, lines)
	if err != nil {
		t.Fatal(err)
	}
	result := evaluate(&c, &StatusUpdate{Status: "confirmed"}, false)
	if result.Status != StatusBlocked {
		t.Fatalf("missing guard effect should block confirmation, got %+v", result)
	}
	err = applyDrafts(&c, nil, nil, []FactDraft{{Type: "guard_condition", Content: map[string]any{"effect": "not_dominating"}, File: "A.java", Line: 2, Proof: []Proof{{File: "A.java", Line: 2}}}}, lines)
	if err != nil {
		t.Fatal(err)
	}
	result = evaluate(&c, &StatusUpdate{Status: "confirmed"}, false)
	if result.Status != StatusConfirmed {
		t.Fatalf("closed non-blocking guard effect should allow confirmation, got %+v", result)
	}
}
