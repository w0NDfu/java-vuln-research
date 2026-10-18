package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vecho_final/scaner/internal/config"
	"vecho_final/scaner/internal/contextaudit"
	"vecho_final/scaner/internal/llm"
	"vecho_final/scaner/internal/memorymcp"
	"vecho_final/scaner/internal/model"
	"vecho_final/scaner/internal/output"
	"vecho_final/scaner/internal/planner"
	"vecho_final/scaner/internal/repo"
	rescanpkg "vecho_final/scaner/internal/rescan"
	"vecho_final/scaner/internal/scanner"
	"vecho_final/scaner/internal/seedscan"
	"vecho_final/scaner/internal/session"
	"vecho_final/scaner/internal/vecho"
)

func RunScan(ctx context.Context, cfg config.Config) error {
	return runConfigured(ctx, cfg, runHooks{})
}

func RunRescan(ctx context.Context, cfg config.Config) error {
	input, prepared, err := prepareRescan(ctx, cfg)
	if err != nil {
		return err
	}
	return runConfigured(ctx, prepared, runHooks{
		Plan: func(_ model.Inventory, plan model.Plan) (model.Plan, error) {
			return rescanpkg.ApplyGuidancePlan(plan, input.Guidance, input.Bundle), nil
		},
		AfterStoreInit: func(store *session.Store) error {
			return saveRescanArtifacts(store.Dir, input)
		},
	})
}

type runHooks struct {
	Plan           func(model.Inventory, model.Plan) (model.Plan, error)
	AfterStoreInit func(*session.Store) error
}

func runConfigured(ctx context.Context, cfg config.Config, hooks runHooks) error {
	if _, err := os.Stat(filepath.Join(cfg.OutDir, "session.json")); err == nil {
		return fmt.Errorf("session already exists; use resume instead of overwriting %s", cfg.OutDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	store := session.NewStore(cfg.OutDir)
	if err := store.Init(); err != nil {
		return err
	}
	if hooks.AfterStoreInit != nil {
		if err := hooks.AfterStoreInit(store); err != nil {
			return err
		}
	}
	_ = os.Remove(filepath.Join(cfg.OutDir, "events.ndjson"))
	_ = os.Remove(store.SeedsNDJSONPath)
	_ = os.Remove(store.TranscriptPath)
	meta := session.Metadata{SessionID: cfg.SessionID, RepoPath: cfg.RepoPath, OutDir: cfg.OutDir, Config: redactedConfig(cfg), Status: "running", StartedAt: time.Now().UTC()}
	if err := store.SaveMetadata(meta); err != nil {
		return err
	}
	events, err := output.NewEventBus(cfg.SessionID, filepath.Join(cfg.OutDir, "events.ndjson"), cfg.Format, os.Stdout)
	if err != nil {
		return err
	}
	defer events.Close()
	if err := events.Emit(model.Event{Type: "session_started", Data: map[string]interface{}{"repo_path": cfg.RepoPath, "out_dir": cfg.OutDir, "use_llm": cfg.UseLLM}}); err != nil {
		return err
	}

	inv, err := repo.Analyzer{}.Analyze(ctx, cfg.RepoPath, cfg.LanguageHint)
	if err != nil {
		return finishWithError(store, events, meta, err)
	}
	if err := store.SaveInventory(inv); err != nil {
		return finishWithError(store, events, meta, err)
	}
	_ = events.Emit(model.Event{Type: "repo_inventory", Data: inv})

	plan := planner.Planner{}.Build(inv)
	if hooks.Plan != nil {
		plan, err = hooks.Plan(inv, plan)
		if err != nil {
			return finishWithError(store, events, meta, err)
		}
	}
	if err := store.SavePlan(plan); err != nil {
		return finishWithError(store, events, meta, err)
	}
	_ = events.Emit(model.Event{Type: "plan_created", Data: plan})

	ag := seedscan.New(cfg, store, events)
	seeds, plan, err := ag.Run(ctx, inv, plan)
	if err != nil {
		return finishWithError(store, events, meta, err)
	}
	seedUsage := ag.LLM.Usage()
	if err := store.SavePlan(plan); err != nil {
		return finishWithError(store, events, meta, err)
	}
	if err := store.SaveSeeds(seeds); err != nil {
		return finishWithError(store, events, meta, err)
	}
	_ = events.Emit(model.Event{Type: "seed_discovery_completed", Data: map[string]interface{}{"seed_count": len(seeds)}})
	ctxSummary, err := contextaudit.NewRunner(cfg, contextaudit.NewStore(cfg.OutDir), events).Run(ctx, seeds)
	if err != nil {
		return finishWithError(store, events, meta, err)
	}
	return finishSuccess(store, events, meta, seeds, plan, ctxSummary, usageSummary(seedUsage, ctxSummary.Usage))
}

func prepareRescan(ctx context.Context, cfg config.Config) (rescanpkg.Input, config.Config, error) {
	cfg.Mode = rescanpkg.Mode
	cfg.VechoSourceScanner = rescanpkg.SourceScanner
	var bundle rescanpkg.Bundle
	var err error
	if strings.TrimSpace(cfg.RescanBundlePath) != "" {
		bundle, err = rescanpkg.LoadBundle(cfg.RescanBundlePath)
		if err != nil {
			return rescanpkg.Input{}, config.Config{}, err
		}
	} else {
		if strings.TrimSpace(cfg.RescanGuidancePath) == "" {
			return rescanpkg.Input{}, config.Config{}, errors.New("rescan requires --bundle or --guidance")
		}
		bundle = rescanpkg.Bundle{
			ProjectID:            firstNonEmpty(cfg.ProjectID, cfg.ProjectName, "project"),
			RepoPath:             cfg.RepoPath,
			KnownVulnerabilities: []vecho.VulnerabilityRecord{},
			Guidance:             []rescanpkg.GuidanceRecord{},
		}
	}
	extraGuidance, err := rescanpkg.LoadGuidance(cfg.RescanGuidancePath)
	if err != nil {
		return rescanpkg.Input{}, config.Config{}, err
	}
	if strings.TrimSpace(cfg.RepoPath) == "" {
		cfg.RepoPath = bundle.RepoPath
	}
	if strings.TrimSpace(cfg.ProjectID) == "" {
		cfg.ProjectID = bundle.ProjectID
	}
	if strings.TrimSpace(bundle.ProjectID) == "" {
		bundle.ProjectID = firstNonEmpty(cfg.ProjectID, cfg.ProjectName, "project")
	}
	if strings.TrimSpace(bundle.RepoPath) == "" {
		bundle.RepoPath = cfg.RepoPath
	}
	if bundle.KnownVulnerabilities == nil {
		bundle.KnownVulnerabilities = []vecho.VulnerabilityRecord{}
	}
	if bundle.Guidance == nil {
		bundle.Guidance = []rescanpkg.GuidanceRecord{}
	}
	guidance := rescanpkg.MergeGuidance(bundle, extraGuidance)
	promptText := rescanpkg.BuildPromptText(bundle, guidance, 16000)
	if cfg.MemoryMCP.Enabled {
		memoryText := queryRescanMemory(ctx, cfg, guidance)
		if strings.TrimSpace(memoryText) != "" {
			promptText += "\n\nMemory MCP guidance:\n" + memoryText
		}
	}
	cfg.RescanGuidancePrompt = promptText
	if err := cfg.Normalize(); err != nil {
		return rescanpkg.Input{}, config.Config{}, err
	}
	return rescanpkg.Input{Bundle: bundle, Guidance: guidance, PromptText: promptText}, cfg, nil
}

func queryRescanMemory(ctx context.Context, cfg config.Config, guidance []rescanpkg.GuidanceRecord) string {
	var query string
	for _, item := range guidance {
		if len(item.Tags) > 0 {
			query = strings.Join(item.Tags, " ")
			break
		}
		if strings.TrimSpace(item.Content) != "" {
			query = item.Content
			if len(query) > 400 {
				query = query[:400]
			}
			break
		}
	}
	if strings.TrimSpace(query) == "" {
		return ""
	}
	answer, err := memorymcp.New(cfg.MemoryMCP).QueryKnowledge(ctx, query)
	if err != nil {
		return "Memory MCP query failed: " + err.Error()
	}
	return answer
}

func saveRescanArtifacts(outDir string, input rescanpkg.Input) error {
	dir := filepath.Join(outDir, "rescan")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := output.WriteJSON(filepath.Join(dir, "bundle.json"), input.Bundle); err != nil {
		return err
	}
	if err := output.WriteJSON(filepath.Join(dir, "guidance.json"), input.Guidance); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "guidance_prompt.txt"), []byte(input.PromptText), 0o600)
}

func Resume(ctx context.Context, cfg config.Config) error {
	abs, err := filepath.Abs(cfg.ResumeSessionDir)
	if err != nil {
		return err
	}
	meta, err := session.LoadMetadata(abs)
	if err != nil {
		return err
	}
	stored := meta.Config
	stored.APIKey = cfg.APIKey
	if strings.TrimSpace(stored.APIKey) == "" {
		return errors.New("API key is required to resume; set VECHO_SCAN_API_KEY or SILICONFLOW_API_KEY")
	}
	stored.UseLLM = true
	stored.Timeout = cfg.Timeout
	stored.ResumeSessionDir = abs
	meta.Config = redactedConfig(stored)
	meta.Status = "running"
	meta.Error = ""
	normalizeStoredMode(&stored)
	store := session.NewStore(abs)
	if err := store.Init(); err != nil {
		return err
	}
	events, err := output.NewEventBus(stored.SessionID, filepath.Join(abs, "events.ndjson"), stored.Format, os.Stdout)
	if err != nil {
		return err
	}
	defer events.Close()
	_ = events.Emit(model.Event{Type: "session_resumed", Data: map[string]interface{}{"session": abs, "use_llm": stored.UseLLM}})
	inv, err := store.LoadInventory()
	if err != nil {
		return err
	}
	plan, err := store.LoadPlan()
	if err != nil {
		return err
	}
	ag := seedscan.New(stored, store, events)
	if existingSeeds, loadErr := store.LoadSeeds(); loadErr == nil {
		for _, seed := range existingSeeds {
			_, _, _ = ag.Collector.Add(seed)
		}
	}
	seeds, plan, err := ag.Run(ctx, inv, plan)
	if err != nil {
		return finishWithError(store, events, meta, err)
	}
	seedUsage := ag.LLM.Usage()
	if err := store.SavePlan(plan); err != nil {
		return finishWithError(store, events, meta, err)
	}
	if err := store.SaveSeeds(seeds); err != nil {
		return finishWithError(store, events, meta, err)
	}
	_ = events.Emit(model.Event{Type: "seed_discovery_completed", Data: map[string]interface{}{"seed_count": len(seeds)}})
	ctxSummary, err := contextaudit.NewRunner(stored, contextaudit.NewStore(stored.OutDir), events).Run(ctx, seeds)
	if err != nil {
		return finishWithError(store, events, meta, err)
	}
	return finishSuccess(store, events, meta, seeds, plan, ctxSummary, usageSummary(seedUsage, ctxSummary.Usage))
}

func ResumeRescan(ctx context.Context, cfg config.Config) error {
	cfg.Mode = rescanpkg.Mode
	cfg.VechoSourceScanner = rescanpkg.SourceScanner
	return Resume(ctx, cfg)
}

func finishSuccess(store *session.Store, events *output.EventBus, meta session.Metadata, seeds []model.Seed, plan model.Plan, ctxSummary contextaudit.Summary, usage session.UsageSummary) error {
	if err := store.SavePlan(plan); err != nil {
		return err
	}
	if err := store.SaveSeeds(seeds); err != nil {
		return err
	}
	if err := store.SaveUsage(usage); err != nil {
		return err
	}
	if err := store.WriteSummary(scanner.Summary(seeds) + "\n" + contextauditMarkdownSummary(ctxSummary) + "\n" + usageMarkdownSummary(usage)); err != nil {
		return err
	}
	if ctxSummary.Failed > 0 {
		meta.Status = "incomplete"
		meta.Error = fmt.Sprintf("%d contextaudit cases failed; successful checkpoints preserved", ctxSummary.Failed)
		if err := store.SaveMetadata(meta); err != nil {
			return err
		}
		_ = events.Emit(model.Event{Type: modeFor(meta.Config) + "_incomplete", Error: meta.Error, Data: ctxSummary})
		return errors.New(meta.Error)
	}
	meta.Status = "completed"
	meta.Error = ""
	if err := store.SaveMetadata(meta); err != nil {
		return err
	}
	var vechoSummary *vecho.Summary
	if meta.Config.VechoReport {
		summary, err := vecho.ExportSession(meta.OutDir, vecho.Options{
			OutDir:         meta.Config.VechoOut,
			ProjectID:      meta.Config.ProjectID,
			ProjectName:    meta.Config.ProjectName,
			ProjectVersion: meta.Config.ProjectVersion,
			Technology:     meta.Config.Technology,
			ScannerVersion: meta.Config.ScannerVersion,
			SourceScanner:  sourceScannerFor(meta.Config),
			Mode:           modeFor(meta.Config),
		})
		if err != nil {
			return err
		}
		vechoSummary = &summary
	}
	byKind := map[model.SeedKind]int{}
	byFocus := map[string]int{}
	for _, seed := range seeds {
		byKind[seed.Kind]++
		for _, focus := range seed.AuditFocus.SASTGapFocus {
			byFocus[focus]++
		}
	}
	completed := model.Event{Type: modeFor(meta.Config) + "_completed", Data: map[string]interface{}{"seed_count": len(seeds), "by_kind": byKind, "by_sast_gap_focus": byFocus, "contextaudit": ctxSummary, "usage": usage, "vecho_report": vechoSummary}}
	if err := events.Emit(completed); err != nil {
		return err
	}
	if meta.Config.Format == "json" {
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
			"session_id":   meta.SessionID,
			"out_dir":      meta.OutDir,
			"seed_count":   len(seeds),
			"seeds":        seeds,
			"contextaudit": ctxSummary,
			"usage":        usage,
			"vecho_report": vechoSummary,
		})
	}
	return nil
}

func modeFor(cfg config.Config) string {
	if strings.TrimSpace(cfg.Mode) == "rescan" {
		return "rescan"
	}
	return "scan"
}

func sourceScannerFor(cfg config.Config) string {
	if strings.TrimSpace(cfg.VechoSourceScanner) != "" {
		return cfg.VechoSourceScanner
	}
	if modeFor(cfg) == "rescan" {
		return rescanpkg.SourceScanner
	}
	return vecho.DefaultSourceScanner
}

func normalizeStoredMode(cfg *config.Config) {
	if strings.TrimSpace(cfg.Mode) == "" {
		cfg.Mode = "scan"
	}
	if strings.TrimSpace(cfg.VechoSourceScanner) == "" {
		cfg.VechoSourceScanner = sourceScannerFor(*cfg)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func usageSummary(seedDiscovery llm.Usage, contextAudit llm.Usage) session.UsageSummary {
	total := seedDiscovery
	total.Add(contextAudit)
	return session.UsageSummary{SeedDiscovery: seedDiscovery, ContextAudit: contextAudit, Total: total}
}

func contextauditMarkdownSummary(summary contextaudit.Summary) string {
	var b strings.Builder
	b.WriteString("## ContextAudit\n\n")
	b.WriteString(fmt.Sprintf("Total cases: %d\n\n", summary.Total))
	for _, status := range []contextaudit.CaseStatus{contextaudit.StatusConfirmed, contextaudit.StatusDeadEnd, contextaudit.StatusBlocked, contextaudit.StatusRejected, contextaudit.StatusExploring} {
		if count := summary.ByStatus[status]; count > 0 {
			b.WriteString(fmt.Sprintf("- %s: %d\n", status, count))
		}
	}
	return b.String()
}

func usageMarkdownSummary(summary session.UsageSummary) string {
	var b strings.Builder
	b.WriteString("## Token Usage\n\n")
	writeUsage := func(label string, usage llm.Usage) {
		b.WriteString(fmt.Sprintf("- %s: total=%d, prompt=%d, completion=%d", label, usage.TotalTokens, usage.PromptTokens, usage.CompletionTokens))
		if usage.ReasoningTokens > 0 {
			b.WriteString(fmt.Sprintf(", reasoning=%d", usage.ReasoningTokens))
		}
		if usage.PromptCacheHitTokens > 0 || usage.PromptCacheMissTokens > 0 {
			b.WriteString(fmt.Sprintf(", cache_hit=%d, cache_miss=%d", usage.PromptCacheHitTokens, usage.PromptCacheMissTokens))
		}
		b.WriteString("\n")
	}
	writeUsage("seed_discovery", summary.SeedDiscovery)
	writeUsage("contextaudit", summary.ContextAudit)
	writeUsage("total", summary.Total)
	return b.String()
}

func finishWithError(store *session.Store, events *output.EventBus, meta session.Metadata, err error) error {
	meta.Status = "failed"
	meta.Error = err.Error()
	_ = store.SaveMetadata(meta)
	_ = events.Emit(model.Event{Type: "scan_failed", Error: err.Error()})
	return err
}

func redactedConfig(cfg config.Config) config.Config {
	cfg.APIKey = ""
	return cfg
}
