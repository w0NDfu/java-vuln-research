package seedscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vecho_final/scaner/internal/config"
	"vecho_final/scaner/internal/llm"
	"vecho_final/scaner/internal/model"
	"vecho_final/scaner/internal/output"
	"vecho_final/scaner/internal/scanner"
	"vecho_final/scaner/internal/session"
	"vecho_final/scaner/internal/tools"
)

type Runner struct {
	Config    config.Config
	Store     *session.Store
	Events    *output.EventBus
	Tools     *tools.Registry
	LLM       *llm.Client
	Collector *scanner.Collector

	toolIndex int
}

func New(cfg config.Config, store *session.Store, events *output.EventBus) *Runner {
	client := &llm.Client{BaseURL: cfg.BaseURL, APIKey: cfg.APIKey, Model: cfg.Model, DiagnosticPath: filepath.Join(cfg.OutDir, "llm-attempts.ndjson")}
	r := &Runner{Config: cfg, Store: store, Events: events, Tools: tools.NewRegistry(cfg.AllowMutatingBash), LLM: client, Collector: scanner.NewCollector()}
	if cfg.ResumeSessionDir != "" {
		files, _ := os.ReadDir(store.ToolResultDir)
		for _, f := range files {
			var n int
			if _, err := fmt.Sscanf(f.Name(), "%d-", &n); err == nil && n > r.toolIndex {
				r.toolIndex = n
			}
		}
	}
	return r
}

func (a *Runner) Run(ctx context.Context, inv model.Inventory, plan model.Plan) ([]model.Seed, model.Plan, error) {
	for i := range plan.Blocks {
		if plan.Blocks[i].Status == model.BlockCompleted || plan.Blocks[i].Status == model.BlockSkippedWithReason {
			continue
		}
		plan.Blocks[i].Status = model.BlockInProgress
		plan.Blocks[i].StartedAt = time.Now().UTC()
		_ = a.Store.SavePlan(plan)
		_ = a.Events.Emit(model.Event{Type: "block_started", BlockID: plan.Blocks[i].ID, Data: plan.Blocks[i]})
		err := a.runLLMBlock(ctx, inv, &plan, i)
		if err != nil {
			return a.Collector.Seeds(), plan, err
		}
		if plan.Blocks[i].Status == model.BlockInProgress || plan.Blocks[i].Status == model.BlockPending {
			plan.Blocks[i].Status = model.BlockCompleted
			plan.Blocks[i].CompletedAt = time.Now().UTC()
			if plan.Blocks[i].Summary == "" {
				plan.Blocks[i].Summary = "Block completed by LLM-guided scan; see emitted seeds and tool transcript."
			}
		}
		_ = a.Store.SavePlan(plan)
		_ = a.Events.Emit(model.Event{Type: "block_completed", BlockID: plan.Blocks[i].ID, Data: plan.Blocks[i]})
	}
	seeds := a.Collector.Seeds()
	return seeds, plan, nil
}

func (a *Runner) runLLMBlock(ctx context.Context, inv model.Inventory, plan *model.Plan, index int) error {
	block := &plan.Blocks[index]
	messages := []llm.Message{{Role: "system", Content: systemPrompt()}, {Role: "user", Content: blockPrompt(inv, *plan, *block, a.Config.MaxFilesPerBlock, a.Config.RescanGuidancePrompt)}}
	for turn := 0; turn < a.Config.MaxTurnsPerBlock; turn++ {
		cctx, cancel := context.WithTimeout(ctx, a.Config.Timeout)
		result, err := a.LLM.ChatWithUsage(cctx, messages)
		cancel()
		if err != nil {
			return err
		}
		content := result.Content
		_ = a.Store.AppendTranscript(map[string]interface{}{"role": "assistant", "block_id": block.ID, "content": content, "usage": result.Usage})
		action, err := llm.ParseAction(content)
		if err != nil {
			messages = append(messages, llm.Message{Role: "assistant", Content: content}, llm.Message{Role: "user", Content: "Your previous response was not valid JSON for the required action schema. Return only a JSON object with tool_calls, emit_seed, update_block_status, or finalize."})
			continue
		}
		for _, seed := range action.EmitSeeds {
			seed.ScanBlockID = block.ID
			seed = a.fillSeedDefaults(seed, *block)
			if err := a.emitSeed(seed, block); err != nil {
				_ = a.Store.AppendTranscript(map[string]interface{}{"role": "system", "block_id": block.ID, "message": "seed rejected: " + err.Error()})
			}
		}
		if len(action.ToolCalls) > 0 {
			if turn == a.Config.MaxTurnsPerBlock-1 {
				block.Status = model.BlockSkippedWithReason
				block.CompletedAt = time.Now().UTC()
				block.SkippedReason = "LLM requested more tools on the final turn; increase --max-turns-per-block to inspect further."
				block.Summary = "Block stopped at the LLM turn budget before a final seed/status response."
				return nil
			}
			batchSummaries := make([]string, 0, len(action.ToolCalls))
			for _, call := range action.ToolCalls {
				result := a.executeTool(ctx, call, block)
				block.ToolCalls++
				batchSummaries = append(batchSummaries, summarizeToolResult(result))
			}
			remaining := a.Config.MaxTurnsPerBlock - turn - 1
			nextInstruction := fmt.Sprintf("You have %d response turn(s) remaining for this block. Continue only if essential; otherwise emit seeds and update_block_status=completed.", remaining)
			if remaining <= 1 {
				nextInstruction = "This is your final response opportunity for this block. Do not call more tools. Emit any seeds supported by the gathered evidence, then set update_block_status.status to completed or skipped_with_reason."
			}
			messages = append(messages, llm.Message{Role: "assistant", Content: content}, llm.Message{Role: "user", Content: "Tool results from the latest requested batch:\n" + strings.Join(batchSummaries, "\n\n") + "\n" + nextInstruction})
			continue
		}
		if action.UpdateBlockStatus != nil {
			applyBlockUpdate(block, *action.UpdateBlockStatus)
			if block.Status == model.BlockCompleted || block.Status == model.BlockSkippedWithReason {
				block.CompletedAt = time.Now().UTC()
				return nil
			}
		}
		if action.Finalize || len(action.ToolCalls) == 0 {
			block.Status = model.BlockCompleted
			block.CompletedAt = time.Now().UTC()
			if block.Summary == "" {
				block.Summary = action.Thought
			}
			return nil
		}
	}
	return fmt.Errorf("max turns reached for %s", block.ID)
}

func (a *Runner) executeTool(ctx context.Context, call model.ToolCallRequest, block *model.ScanBlock) tools.ToolResult {
	if call.ID == "" {
		call.ID = fmt.Sprintf("tool-%06d", a.toolIndex+1)
	}
	tc := tools.ToolContext{RepoRoot: a.Config.RepoPath, ActiveBlock: block, AllowMutatingBash: a.Config.AllowMutatingBash, Timeout: a.Config.Timeout}
	result, err := a.Tools.Call(ctx, call, tc)
	if err != nil {
		result.Error = err.Error()
	}
	a.toolIndex++
	path := a.Store.ToolResultPath(a.toolIndex, result.Tool)
	_ = output.WriteJSON(path, result)
	_ = a.Store.AppendTranscript(map[string]interface{}{"role": "tool", "block_id": block.ID, "tool": result.Tool, "args": json.RawMessage(call.Args), "result_path": path, "error": result.Error})
	_ = a.Events.Emit(model.Event{Type: "tool_call", BlockID: block.ID, Tool: result.Tool, Data: map[string]interface{}{"args": json.RawMessage(call.Args), "result_path": path, "truncated": result.Truncated}, Error: result.Error})
	return result
}

func (a *Runner) emitSeed(seed model.Seed, block *model.ScanBlock) error {
	added, isNew, err := a.Collector.Add(seed)
	if err != nil {
		return err
	}
	if isNew {
		block.SeedsFound++
		_ = a.Store.AppendSeed(added)
		_ = a.Events.Emit(model.Event{Type: "seed_found", BlockID: block.ID, Seed: &added})
	} else {
		_ = a.Events.Emit(model.Event{Type: "seed_merged", BlockID: block.ID, Seed: &added})
	}
	return nil
}

func (a *Runner) fillSeedDefaults(seed model.Seed, block model.ScanBlock) model.Seed {
	if seed.Confidence == "" {
		seed.Confidence = model.ConfidenceMedium
	}
	if len(seed.AuditFocus.SASTGapFocus) == 0 {
		seed.AuditFocus.SASTGapFocus = append([]string(nil), block.SASTGapFocus...)
	}
	if seed.AuditFocus.WhyStaticAnalysisMayMiss == "" {
		seed.AuditFocus.WhyStaticAnalysisMayMiss = block.WhyStaticAnalysisMayMiss
	}
	if seed.ScanBlockID == "" {
		seed.ScanBlockID = block.ID
	}
	if seed.Module == "" {
		seed.Module = moduleFromPath(seed.Location.File)
	}
	return seed
}

func applyBlockUpdate(block *model.ScanBlock, update model.BlockUpdate) {
	if update.Status != "" {
		block.Status = update.Status
	}
	if update.Summary != "" {
		block.Summary = update.Summary
	}
	if update.SkippedReason != "" {
		block.SkippedReason = update.SkippedReason
	}
	if update.StaticAnalysisHypothesis != "" {
		ok := !strings.Contains(strings.ToLower(update.StaticAnalysisHypothesis), "denied") && !strings.Contains(strings.ToLower(update.StaticAnalysisHypothesis), "false")
		block.StaticAnalysisHypothesisOK = &ok
	}
}

func summarizeToolResult(result tools.ToolResult) string {
	text := strings.TrimSpace(result.DisplayText)
	if len(text) > 1600 {
		text = text[:1600] + "\n[truncated for prompt]"
	}
	if result.Error != "" {
		return fmt.Sprintf("%s error: %s\n%s", result.Tool, result.Error, text)
	}
	return fmt.Sprintf("%s result:\n%s", result.Tool, text)
}

func moduleFromPath(path string) string {
	path = filepath.ToSlash(path)
	parts := strings.Split(path, "/")
	if len(parts) >= 3 && parts[0] == "src" {
		return strings.Join(parts[:3], "/")
	}
	if len(parts) > 0 {
		return parts[0]
	}
	return "repo"
}
