package contextaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vecho_final/scaner/internal/config"
	"vecho_final/scaner/internal/llm"
	"vecho_final/scaner/internal/model"
	"vecho_final/scaner/internal/tools"
)

type Runner struct {
	Config config.Config
	Store  *Store
	Events interface{ Emit(model.Event) error }
	Tools  *tools.Registry
	LLM    *llm.Client
}

func NewRunner(cfg config.Config, store *Store, events interface{ Emit(model.Event) error }) *Runner {
	return &Runner{
		Config: cfg,
		Store:  store,
		Events: events,
		Tools:  tools.NewRegistry(cfg.AllowMutatingBash),
		LLM:    &llm.Client{BaseURL: cfg.BaseURL, APIKey: cfg.APIKey, Model: cfg.Model, DiagnosticPath: filepath.Join(cfg.OutDir, "llm-attempts.ndjson"), AttemptTimeout: cfg.Timeout},
	}
}

func (r *Runner) Run(ctx context.Context, seeds []model.Seed) (Summary, error) {
	started := time.Now().UTC()
	if err := r.Store.Init(); err != nil {
		return Summary{}, err
	}
	ordered := sortedSeeds(seeds)
	if r.Config.MaxContextCases > 0 && len(ordered) > r.Config.MaxContextCases {
		ordered = ordered[:r.Config.MaxContextCases]
	}
	concurrency := r.contextConcurrency(len(ordered))
	_ = r.emit(model.Event{Type: "contextaudit_started", Data: map[string]any{"case_count": len(ordered), "concurrency": concurrency}})

	results := make([]CaseResult, len(ordered))
	reused := make([]bool, len(ordered))
	if r.Config.ResumeSessionDir != "" {
		for i, seed := range ordered {
			saved, ok, err := r.reusableCheckpoint(i+1, seed)
			if err != nil {
				return Summary{}, err
			}
			if ok {
				results[i] = saved
				reused[i] = true
			}
		}
	}
	if len(ordered) > 0 {
		type job struct {
			index int
			seed  model.Seed
		}
		jobs := make(chan job)
		errCh := make(chan error, 1)
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		var wg sync.WaitGroup
		for worker := 0; worker < concurrency; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range jobs {
					if ctx.Err() != nil {
						return
					}
					result, err := r.runSeed(ctx, j.index+1, j.seed)
					if err != nil {
						if ctx.Err() == nil {
							result = CaseResult{CaseID: fmt.Sprintf("case-%06d", j.index+1), SeedID: j.seed.ID, SeedKind: j.seed.Kind, Status: StatusFailed, Reason: err.Error()}
							if saveErr := r.Store.SaveResult(result); saveErr == nil {
								results[j.index] = result
								_ = r.emit(model.Event{Type: "case_failed", Error: err.Error(), Data: result})
								continue
							} else {
								err = saveErr
							}
						}
						select {
						case errCh <- err:
							cancel()
						default:
						}
						return
					}
					results[j.index] = result
				}
			}()
		}
	sendLoop:
		for i, seed := range ordered {
			if reused[i] {
				_ = r.emit(model.Event{Type: "case_reused", Data: results[i]})
				continue
			}
			select {
			case <-ctx.Done():
				break sendLoop
			case jobs <- job{index: i, seed: seed}:
			}
		}
		close(jobs)
		wg.Wait()
		select {
		case err := <-errCh:
			return Summary{}, err
		default:
		}
		if err := ctx.Err(); err != nil {
			return Summary{}, err
		}
	}
	summary := Summary{Total: len(results), ByStatus: map[CaseStatus]int{}, Results: results, StartedAt: started, EndedAt: time.Now().UTC()}
	summary.UsageScope = "current attempt only; reused checkpoints and failed HTTP requests are not billed-usage totals"
	for _, ok := range reused {
		if ok {
			summary.Reused++
		}
	}
	for _, result := range results {
		summary.ByStatus[result.Status]++
		if result.Status == StatusFailed {
			summary.Failed++
		}
	}
	summary.Usage = r.LLM.Usage()
	if err := r.Store.SaveSummary(summary); err != nil {
		return Summary{}, err
	}
	_ = r.emit(model.Event{Type: "contextaudit_completed", Data: summary})
	return summary, nil
}

func (r *Runner) runSeed(ctx context.Context, index int, seed model.Seed) (CaseResult, error) {
	c := newCase(index, seed)
	if r.Config.ResumeSessionDir != "" {
		if err := r.Store.ArchiveCase(c.CaseID); err != nil {
			return CaseResult{}, err
		}
	}
	if err := r.Store.InitCase(c.CaseID); err != nil {
		return CaseResult{}, err
	}
	_ = r.emit(model.Event{Type: "case_started", Data: map[string]any{"case_id": c.CaseID, "seed_id": seed.ID, "seed_kind": seed.Kind}})

	lineCache := map[string]map[int]string{}
	if err := r.bootstrapCase(ctx, &c, lineCache); err != nil {
		c.Status = StatusRejected
		c.Reason = err.Error()
		result := evaluate(&c, &StatusUpdate{Status: string(StatusRejected), Reason: err.Error()}, false)
		_ = r.Store.SaveCase(c)
		_ = r.Store.SaveResult(result)
		_ = r.emit(model.Event{Type: "case_completed", Data: result})
		return result, nil
	}
	if err := r.Store.SaveCase(c); err != nil {
		return CaseResult{}, err
	}

	var result CaseResult
	for step := 0; step < r.maxContextSteps(); step++ {
		budgetBlocked := c.ToolCalls >= r.maxContextToolCalls()
		if budgetBlocked {
			result = evaluate(&c, nil, true)
			break
		}
		res, done, err := r.runCaseStep(ctx, &c, lineCache)
		if err != nil {
			c.Status = StatusFailed
			c.Reason = err.Error()
			_ = r.Store.SaveCase(c)
			return CaseResult{}, err
		}
		result = res
		if err := r.Store.SaveCase(c); err != nil {
			return CaseResult{}, err
		}
		if done {
			break
		}
		if c.NextQuestion == "" {
			c.NextQuestion = "continue tracing the current chain toward a source-to-sink conclusion"
		}
	}
	if result.CaseID == "" || result.Status == StatusExploring {
		result = evaluate(&c, nil, true)
	}
	if err := r.Store.SaveCase(c); err != nil {
		return CaseResult{}, err
	}
	if err := r.Store.SaveResult(result); err != nil {
		return CaseResult{}, err
	}
	_ = r.emit(model.Event{Type: "case_completed", Data: result})
	return result, nil
}

func (r *Runner) bootstrapCase(ctx context.Context, c *Case, lineCache map[string]map[int]string) error {
	file := fileFromSeed(c.Seed)
	if strings.TrimSpace(file) == "" {
		return fmt.Errorf("seed has no file location")
	}
	line := lineFromSeed(c.Seed)
	offset := line - 40
	if offset < 1 {
		offset = 1
	}
	call := model.ToolCallRequest{Tool: "Read", Args: mustRaw(map[string]any{"file_path": file, "offset": offset, "limit": 120})}
	result := r.executeTool(ctx, c, call, lineCache)
	if result.Error != "" {
		return fmt.Errorf("read seed location: %s", result.Error)
	}
	snippet := lineSnippet(lineCache, filepath.ToSlash(file), line)
	insertEntryStep(c, snippet)
	addInitialFacts(c)
	c.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *Runner) runCaseStep(ctx context.Context, c *Case, lineCache map[string]map[int]string) (CaseResult, bool, error) {
	messages := []llm.Message{{Role: "system", Content: systemPrompt()}, {Role: "user", Content: casePrompt(*c, 5)}}
	var lastResult CaseResult
	for turn := 0; turn < r.maxContextTurns(); turn++ {
		result, err := r.LLM.ChatWithUsage(ctx, messages)
		if err != nil {
			return CaseResult{}, false, err
		}
		content := result.Content
		_ = r.Store.AppendTranscript(c.CaseID, map[string]any{"role": "assistant", "content": content, "usage": result.Usage})
		action, err := parseAction(content)
		if err != nil {
			messages = append(messages, llm.Message{Role: "assistant", Content: content}, llm.Message{Role: "user", Content: "Your previous response was not valid JSON for the required ContextAudit action schema. Return only a JSON object."})
			continue
		}
		for _, call := range action.ToolCalls {
			if c.ToolCalls >= r.maxContextToolCalls() {
				lastResult = evaluate(c, &StatusUpdate{Status: string(StatusBlocked), Reason: "contextaudit tool budget reached"}, true)
				return lastResult, true, nil
			}
			result := r.executeTool(ctx, c, call, lineCache)
			remaining := r.maxContextTurns() - turn - 1
			nextInstruction := fmt.Sprintf("You have %d response turn(s) remaining for this ContextAudit step. Continue tool use only if essential; otherwise add evidenced chain steps/facts and set case_status.", remaining)
			if remaining <= 1 {
				nextInstruction = "This is your final response opportunity for this ContextAudit step. Do not call more tools. Add any steps/facts supported by the gathered evidence, then set case_status to confirmed, dead_end, blocked, rejected, or continue with next_question."
			}
			messages = append(messages, llm.Message{Role: "assistant", Content: content}, llm.Message{Role: "user", Content: "Tool result:\n" + summarizeToolResult(result) + "\n" + nextInstruction})
		}
		if len(action.PrependSteps) > 0 || len(action.AppendSteps) > 0 || len(action.Facts) > 0 {
			if err := applyDrafts(c, action.PrependSteps, action.AppendSteps, action.Facts, lineCache); err != nil {
				if applyErr, ok := err.(*draftApplyError); ok && applyErr.HasApplied() {
					messages = append(messages, llm.Message{Role: "assistant", Content: content}, llm.Message{Role: "user", Content: "Graph update partially applied by engine: " + err.Error() + ". Valid steps/facts were kept. Fix only the rejected items using lines already read or call Read/Grep first."})
				} else {
					messages = append(messages, llm.Message{Role: "assistant", Content: content}, llm.Message{Role: "user", Content: "Graph update rejected by engine: " + err.Error() + ". Fix the proof using lines already read or call Read/Grep first."})
				}
				continue
			}
		}
		if strings.TrimSpace(action.NextQuestion) != "" {
			c.NextQuestion = strings.TrimSpace(action.NextQuestion)
		}
		lastResult = evaluate(c, action.CaseStatus, false)
		if lastResult.Status != StatusExploring {
			return lastResult, true, nil
		}
		if len(action.ToolCalls) == 0 {
			return lastResult, false, nil
		}
	}
	lastResult = evaluate(c, &StatusUpdate{Status: string(StatusBlocked), Reason: "contextaudit turn budget reached for current step"}, true)
	return lastResult, true, nil
}

func (r *Runner) executeTool(ctx context.Context, c *Case, call model.ToolCallRequest, lineCache map[string]map[int]string) tools.ToolResult {
	tc := tools.ToolContext{RepoRoot: r.Config.RepoPath, ActiveBlock: nil, AllowMutatingBash: r.Config.AllowMutatingBash, Timeout: r.Config.Timeout}
	result, err := r.Tools.Call(ctx, call, tc)
	if err != nil {
		result.Error = err.Error()
	}
	c.ToolCalls++
	path, _ := r.Store.SaveToolResult(c.CaseID, c.ToolCalls, result)
	_ = r.Store.AppendTranscript(c.CaseID, map[string]any{"role": "tool", "tool": result.Tool, "args": json.RawMessage(call.Args), "result_path": path, "error": result.Error})
	_ = r.emit(model.Event{Type: "contextaudit_tool_call", Tool: result.Tool, Data: map[string]any{"case_id": c.CaseID, "args": json.RawMessage(call.Args), "result_path": path, "truncated": result.Truncated}, Error: result.Error})
	if result.Tool == "Read" && result.Error == "" {
		r.recordRead(c, result, lineCache)
	}
	return result
}

func (r *Runner) recordRead(c *Case, result tools.ToolResult, lineCache map[string]map[int]string) {
	out, ok := result.Data.(tools.ReadOutput)
	if !ok {
		return
	}
	file := filepath.ToSlash(out.Relative)
	if lineCache[file] == nil {
		lineCache[file] = map[int]string{}
	}
	for _, line := range strings.Split(strings.TrimRight(out.Content, "\n"), "\n") {
		idx := strings.Index(line, "\t")
		if idx < 0 {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(line[:idx]), "%d", &n); err != nil || n <= 0 {
			continue
		}
		lineCache[file][n] = strings.TrimRight(line[idx+1:], "\r")
	}
	end := out.Offset + out.LinesRead - 1
	c.ReadWindows = append(c.ReadWindows, ReadWindow{File: file, StartLine: out.Offset, EndLine: end, SHA256: out.SHA256})
	c.UpdatedAt = time.Now().UTC()
}

func (r *Runner) emit(event model.Event) error {
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	if event.SessionID == "" {
		event.SessionID = r.Config.SessionID
	}
	_ = r.Store.Emit(event)
	if r.Events != nil {
		return r.Events.Emit(event)
	}
	return nil
}

func (r *Runner) maxContextSteps() int {
	if r.Config.MaxContextStepsPerCase > 0 {
		return r.Config.MaxContextStepsPerCase
	}
	return 8
}

func (r *Runner) maxContextTurns() int {
	if r.Config.MaxContextTurnsPerStep > 0 {
		return r.Config.MaxContextTurnsPerStep
	}
	return 6
}

func (r *Runner) maxContextToolCalls() int {
	if r.Config.MaxContextToolCallsPerCase > 0 {
		return r.Config.MaxContextToolCallsPerCase
	}
	return 30
}

func (r *Runner) contextConcurrency(caseCount int) int {
	if caseCount <= 0 {
		return 0
	}
	n := r.Config.ContextConcurrency
	if n <= 0 {
		n = 5
	}
	if n > caseCount {
		return caseCount
	}
	return n
}

func summarizeToolResult(result tools.ToolResult) string {
	text := strings.TrimSpace(result.DisplayText)
	if len(text) > 1800 {
		text = text[:1800] + "\n[truncated for prompt]"
	}
	if result.Error != "" {
		return fmt.Sprintf("%s error: %s\n%s", result.Tool, result.Error, text)
	}
	return fmt.Sprintf("%s result:\n%s", result.Tool, text)
}

func mustRaw(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}
