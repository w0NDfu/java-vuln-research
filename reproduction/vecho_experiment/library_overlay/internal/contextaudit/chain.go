package contextaudit

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"vecho_final/scaner/internal/model"
)

func seedEntryKind(kind model.SeedKind) StepKind {
	switch kind {
	case model.SeedSource:
		return StepSource
	case model.SeedSink:
		return StepSink
	case model.SeedSanitizer:
		return StepSanitizer
	case model.SeedControlPoint:
		return StepGuard
	default:
		return StepPropagation
	}
}

func initialQuestion(seed model.Seed) string {
	switch seed.Kind {
	case model.SeedSource:
		return "trace this source downstream until a security-relevant sink or blocking sanitizer/guard is proven"
	case model.SeedSink:
		return "trace this sink upstream until a real attacker-controlled source or a dead end is proven"
	case model.SeedSanitizer:
		return "verify whether this sanitizer truly blocks the tracked value for the downstream sink semantics, then trace both sides if needed"
	case model.SeedControlPoint:
		return "verify whether this guard controls a dangerous path and trace the relevant source/sink context"
	default:
		return "trace this propagation point both upstream toward a source and downstream toward a sink"
	}
}

func lineFromSeed(seed model.Seed) int {
	if seed.Location.Line > 0 {
		return seed.Location.Line
	}
	for _, ev := range seed.Evidence {
		if ev.Line > 0 {
			return ev.Line
		}
	}
	return 1
}

func fileFromSeed(seed model.Seed) string {
	if strings.TrimSpace(seed.Location.File) != "" {
		return seed.Location.File
	}
	for _, ev := range seed.Evidence {
		if strings.TrimSpace(ev.File) != "" {
			return ev.File
		}
	}
	return ""
}

func newCase(index int, seed model.Seed) Case {
	now := time.Now().UTC()
	return Case{
		CaseID:       fmt.Sprintf("case-%06d", index),
		SeedID:       seed.ID,
		Seed:         seed,
		Status:       StatusExploring,
		NextQuestion: initialQuestion(seed),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func addInitialFacts(c *Case) {
	now := time.Now().UTC()
	add := func(t string, content map[string]any) {
		c.Facts = append(c.Facts, Fact{FactID: fmt.Sprintf("fact-%06d", len(c.Facts)+1), Type: t, Content: content, CreatedAt: now})
	}
	if len(c.Seed.AuditFocus.SASTGapFocus) > 0 || c.Seed.AuditFocus.WhyStaticAnalysisMayMiss != "" {
		add("open_question", map[string]any{
			"sast_gap_focus":               c.Seed.AuditFocus.SASTGapFocus,
			"why_static_analysis_may_miss": c.Seed.AuditFocus.WhyStaticAnalysisMayMiss,
		})
	}
	if c.Seed.PropagationHint != "" {
		add("open_question", map[string]any{"propagation_hint": c.Seed.PropagationHint})
	}
	if len(c.Seed.DownstreamQuestions) > 0 {
		add("open_question", map[string]any{"downstream_questions": c.Seed.DownstreamQuestions})
	}
	if c.Seed.Location.Symbol != "" {
		add("tracked_value", map[string]any{"symbol": c.Seed.Location.Symbol})
	}
}

func insertEntryStep(c *Case, snippet string) {
	step := ChainStep{
		StepID:      "step-000001",
		Kind:        seedEntryKind(c.Seed.Kind),
		Symbol:      c.Seed.Location.Symbol,
		File:        filepath.ToSlash(fileFromSeed(c.Seed)),
		Line:        lineFromSeed(c.Seed),
		Snippet:     firstNonEmpty(snippet, firstEvidenceSnippet(c.Seed)),
		Summary:     firstNonEmpty(c.Seed.Rationale, c.Seed.Title),
		ProofSource: "Read",
		CreatedAt:   time.Now().UTC(),
	}
	c.Steps = []ChainStep{step}
	c.EntryStepID = step.StepID
}

func firstEvidenceSnippet(seed model.Seed) string {
	for _, ev := range seed.Evidence {
		if strings.TrimSpace(ev.Snippet) != "" {
			return strings.TrimSpace(ev.Snippet)
		}
	}
	return ""
}

func applyDrafts(c *Case, prepend []StepDraft, appendSteps []StepDraft, facts []FactDraft, lines map[string]map[int]string) error {
	var problems []string
	appliedSteps := 0
	appliedFacts := 0
	if len(prepend) > 0 {
		steps := make([]ChainStep, 0, len(prepend))
		for i, draft := range prepend {
			step, err := stepFromDraft(c, draft, lines)
			if err != nil {
				problems = append(problems, fmt.Sprintf("prepend_steps[%d]: %v", i, err))
				continue
			}
			steps = append(steps, step)
			appliedSteps++
		}
		if len(steps) > 0 {
			c.Steps = append(steps, c.Steps...)
		}
	}
	for i, draft := range appendSteps {
		step, err := stepFromDraft(c, draft, lines)
		if err != nil {
			problems = append(problems, fmt.Sprintf("append_steps[%d]: %v", i, err))
			continue
		}
		c.Steps = append(c.Steps, step)
		appliedSteps++
	}
	if appliedSteps > 0 {
		renumberSteps(c)
	}
	for i, draft := range facts {
		fact, err := factFromDraft(c, draft, lines)
		if err != nil {
			problems = append(problems, fmt.Sprintf("facts[%d]: %v", i, err))
			continue
		}
		c.Facts = append(c.Facts, fact)
		appliedFacts++
	}
	if appliedSteps > 0 || appliedFacts > 0 {
		c.UpdatedAt = time.Now().UTC()
	}
	if len(problems) > 0 {
		return &draftApplyError{AppliedSteps: appliedSteps, AppliedFacts: appliedFacts, Problems: problems}
	}
	return nil
}

type draftApplyError struct {
	AppliedSteps int
	AppliedFacts int
	Problems     []string
}

func (e *draftApplyError) Error() string {
	prefix := "graph update rejected"
	if e.HasApplied() {
		prefix = "graph update partially applied"
	}
	return fmt.Sprintf("%s: %s", prefix, strings.Join(e.Problems, "; "))
}

func (e *draftApplyError) HasApplied() bool {
	return e != nil && (e.AppliedSteps > 0 || e.AppliedFacts > 0)
}

func stepFromDraft(c *Case, draft StepDraft, lines map[string]map[int]string) (ChainStep, error) {
	if draft.Kind == "" {
		return ChainStep{}, fmt.Errorf("step kind is required")
	}
	if !validStepKind(draft.Kind) {
		return ChainStep{}, fmt.Errorf("unsupported step kind %q", draft.Kind)
	}
	file := filepath.ToSlash(strings.TrimSpace(draft.File))
	line := draft.Line
	if len(draft.Proof) > 0 {
		if file == "" {
			file = filepath.ToSlash(draft.Proof[0].File)
		}
		if line <= 0 {
			line = draft.Proof[0].Line
		}
	}
	proof, err := resolveProofs(draft.Proof, file, line, draft.Snippet, lines)
	if err != nil {
		return ChainStep{}, err
	}
	file = proof.File
	line = proof.Line
	return ChainStep{
		StepID:           fmt.Sprintf("step-%06d", len(c.Steps)+1),
		Kind:             draft.Kind,
		Symbol:           draft.Symbol,
		File:             file,
		Line:             line,
		Snippet:          firstNonEmpty(draft.Snippet, proof.Snippet, lineSnippet(lines, file, line)),
		Summary:          draft.Summary,
		RelationFromPrev: draft.RelationFromPrev,
		ProofSource:      "Read",
		CreatedAt:        time.Now().UTC(),
	}, nil
}

func renumberSteps(c *Case) {
	oldEntry := c.EntryStepID
	entryIdx := -1
	if oldEntry != "" {
		for i := range c.Steps {
			if c.Steps[i].StepID == oldEntry {
				entryIdx = i
				break
			}
		}
	}
	for i := range c.Steps {
		c.Steps[i].StepID = fmt.Sprintf("step-%06d", i+1)
	}
	if entryIdx >= 0 {
		c.EntryStepID = c.Steps[entryIdx].StepID
	} else if len(c.Steps) > 0 && c.EntryStepID == "" {
		c.EntryStepID = c.Steps[0].StepID
	}
}

func factFromDraft(c *Case, draft FactDraft, lines map[string]map[int]string) (Fact, error) {
	if strings.TrimSpace(draft.Type) == "" {
		return Fact{}, fmt.Errorf("fact type is required")
	}
	file := filepath.ToSlash(strings.TrimSpace(draft.File))
	line := draft.Line
	if len(draft.Proof) > 0 {
		if file == "" {
			file = filepath.ToSlash(draft.Proof[0].File)
		}
		if line <= 0 {
			line = draft.Proof[0].Line
		}
	}
	if file != "" || line > 0 || len(draft.Proof) > 0 {
		proof, err := resolveProofs(draft.Proof, file, line, draft.Snippet, lines)
		if err != nil {
			return Fact{}, err
		}
		file = proof.File
		line = proof.Line
		if draft.Snippet == "" {
			draft.Snippet = proof.Snippet
		}
	}
	draft.Content = checkBlockingEvidence(draft, lines)
	return Fact{
		FactID:    fmt.Sprintf("fact-%06d", len(c.Facts)+1),
		Type:      draft.Type,
		Content:   draft.Content,
		File:      file,
		Line:      line,
		Snippet:   firstNonEmpty(draft.Snippet, lineSnippet(lines, file, line)),
		CreatedAt: time.Now().UTC(),
	}, nil
}

type resolvedProof struct {
	File    string
	Line    int
	Snippet string
}

func resolveProofs(proofs []Proof, file string, line int, snippet string, lines map[string]map[int]string) (resolvedProof, error) {
	if len(proofs) == 0 {
		if file == "" || line <= 0 {
			return resolvedProof{}, fmt.Errorf("proof is required")
		}
		proofs = []Proof{{File: file, Line: line, Snippet: snippet}}
	}
	var primary resolvedProof
	for i, proof := range proofs {
		resolved, err := resolveProof(proof, file, line, snippet, lines)
		if err != nil {
			return resolvedProof{}, err
		}
		if i == 0 {
			primary = resolved
		}
	}
	return primary, nil
}

func resolveProof(proof Proof, file string, line int, snippet string, lines map[string]map[int]string) (resolvedProof, error) {
	pf := filepath.ToSlash(strings.TrimSpace(firstNonEmpty(proof.File, file)))
	pl := proof.Line
	if pl <= 0 {
		pl = line
	}
	if pf == "" || pl <= 0 {
		return resolvedProof{}, fmt.Errorf("proof file and line are required")
	}
	want := strings.TrimSpace(firstNonEmpty(proof.Snippet, snippet))
	actual := lineSnippet(lines, pf, pl)
	if actual != "" && (want == "" || snippetMatches(actual, want)) {
		return resolvedProof{File: pf, Line: pl, Snippet: actual}, nil
	}
	if want != "" {
		if corrected, ok := nearbyProofLine(lines, pf, pl, want); ok {
			return resolvedProof{File: pf, Line: corrected, Snippet: lineSnippet(lines, pf, corrected)}, nil
		}
	}
	if actual == "" {
		return resolvedProof{}, fmt.Errorf("proof %s:%d was not read in this case", pf, pl)
	}
	return resolvedProof{}, fmt.Errorf("proof snippet does not match %s:%d", pf, pl)
}

func nearbyProofLine(lines map[string]map[int]string, file string, line int, want string) (int, bool) {
	const maxLineCorrection = 3
	for delta := 1; delta <= maxLineCorrection; delta++ {
		for _, candidate := range []int{line - delta, line + delta} {
			if candidate <= 0 {
				continue
			}
			actual := lineSnippet(lines, file, candidate)
			if actual != "" && snippetMatches(actual, want) {
				return candidate, true
			}
		}
	}
	return 0, false
}

func validStepKind(kind StepKind) bool {
	switch kind {
	case StepSource, StepPropagation, StepSink, StepSanitizer, StepGuard:
		return true
	default:
		return false
	}
}

func lineSnippet(lines map[string]map[int]string, file string, line int) string {
	if line <= 0 {
		return ""
	}
	file = filepath.ToSlash(strings.TrimSpace(file))
	if byLine, ok := lines[file]; ok {
		return strings.TrimSpace(byLine[line])
	}
	return ""
}

func snippetMatches(actual string, want string) bool {
	a := normalizeSnippet(actual)
	w := normalizeSnippet(want)
	return a == w || strings.Contains(a, w) || strings.Contains(w, a)
}

func normalizeSnippet(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

func evaluate(c *Case, proposed *StatusUpdate, budgetBlocked bool) CaseResult {
	source := firstStep(c.Steps, StepSource)
	sink := firstStep(c.Steps, StepSink)
	closure := guardEffectClosure(c)
	proposed = libraryDisposition(c, proposed, closure)
	status := StatusExploring
	reason := "case still has open work"
	if source != nil && sink != nil && sourceBeforeSink(c.Steps) && closure.Closed {
		status = StatusConfirmed
		reason = "source-to-sink chain is present with code evidence"
	} else if source != nil && sink != nil && sourceBeforeSink(c.Steps) && closure.Required {
		reason = closure.Reason
	}
	if proposed != nil {
		switch strings.TrimSpace(proposed.Status) {
		case "dead_end":
			status = StatusDeadEnd
			reason = firstNonEmpty(proposed.Reason, "contextaudit marked the chain as a dead end")
		case "rejected":
			status = StatusRejected
			reason = firstNonEmpty(proposed.Reason, "contextaudit rejected the seed")
		case "blocked":
			status = StatusBlocked
			reason = firstNonEmpty(proposed.Reason, "contextaudit is blocked")
		case "confirmed":
			if status != StatusConfirmed {
				status = StatusBlocked
				if source != nil && sink != nil && sourceBeforeSink(c.Steps) && closure.Required && !closure.Closed {
					reason = closure.Reason
				} else {
					reason = "LLM proposed confirmed, but engine could not verify a source-to-sink chain"
				}
			} else if proposed.Reason != "" {
				reason = proposed.Reason
			}
		}
	}
	if closure.Blocking {
		status = StatusDeadEnd
		reason = closure.Reason
	}
	if budgetBlocked && status == StatusExploring {
		status = StatusBlocked
		if closure.Required && !closure.Closed {
			reason = closure.Reason
		} else {
			reason = "contextaudit budget reached before the case was resolved"
		}
	}
	c.Status = status
	c.Reason = reason
	c.UpdatedAt = time.Now().UTC()
	result := CaseResult{CaseID: c.CaseID, SeedID: c.SeedID, SeedKind: c.Seed.Kind, Status: status, Reason: reason, StepCount: len(c.Steps), FactCount: len(c.Facts)}
	if source != nil {
		result.SourceStepID = source.StepID
	}
	if sink != nil {
		result.SinkStepID = sink.StepID
	}
	return result
}

func firstStep(steps []ChainStep, kind StepKind) *ChainStep {
	for i := range steps {
		if steps[i].Kind == kind {
			return &steps[i]
		}
	}
	return nil
}

func sourceBeforeSink(steps []ChainStep) bool {
	sourceIdx, sinkIdx := -1, -1
	for i, step := range steps {
		if step.Kind == StepSource && sourceIdx < 0 {
			sourceIdx = i
		}
		if step.Kind == StepSink {
			sinkIdx = i
			break
		}
	}
	return sourceIdx >= 0 && sinkIdx >= 0 && sourceIdx < sinkIdx
}

type effectClosure struct {
	Required bool
	Closed   bool
	Blocking bool
	Reason   string
}

func guardEffectClosure(c *Case) effectClosure {
	required := map[string]bool{}
	if c.Seed.Kind == model.SeedSanitizer {
		required["sanitizer_result"] = true
	}
	if c.Seed.Kind == model.SeedControlPoint {
		required["guard_condition"] = true
	}
	for _, step := range c.Steps {
		switch step.Kind {
		case StepSanitizer:
			required["sanitizer_result"] = true
		case StepGuard:
			required["guard_condition"] = true
		}
	}
	latest := map[string]string{}
	for _, fact := range c.Facts {
		t := strings.ToLower(fact.Type)
		if t != "sanitizer_result" && t != "guard_condition" {
			continue
		}
		effect := normalizeEffect(fact.Content["effect"])
		if effect == "" {
			continue
		}
		required[t] = true
		if effect == "blocks" && fact.Content["blocking_evidence_checked"] != true {
			effect = "unknown"
		}
		latest[t] = effect
	}
	if len(required) == 0 {
		return effectClosure{Closed: true}
	}
	var missing []string
	var unknown []string
	for kind := range required {
		switch latest[kind] {
		case "blocks":
			return effectClosure{Required: true, Blocking: true, Reason: fmt.Sprintf("%s effect=blocks prevents confirmation", kind)}
		case "bypassed", "not_dominating", "not_applicable":
			continue
		case "unknown":
			unknown = append(unknown, kind)
		default:
			missing = append(missing, kind)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return effectClosure{Required: true, Reason: fmt.Sprintf("guard/sanitizer effect remains unknown for %s", strings.Join(unknown, ", "))}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return effectClosure{Required: true, Reason: fmt.Sprintf("guard/sanitizer effect is missing for %s", strings.Join(missing, ", "))}
	}
	return effectClosure{Required: true, Closed: true}
}

func normalizeEffect(v any) string {
	effect := strings.ToLower(strings.TrimSpace(fmt.Sprint(v)))
	effect = strings.ReplaceAll(effect, "-", "_")
	switch effect {
	case "blocks", "bypassed", "not_dominating", "not_applicable", "unknown":
		return effect
	default:
		return ""
	}
}

func sortedSeeds(seeds []model.Seed) []model.Seed {
	out := append([]model.Seed(nil), seeds...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].QualityScore == out[j].QualityScore {
			return out[i].ID < out[j].ID
		}
		return out[i].QualityScore > out[j].QualityScore
	})
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
