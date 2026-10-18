package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"vecho_final/scaner/internal/app"
	"vecho_final/scaner/internal/config"
	"vecho_final/scaner/internal/rescan"
	"vecho_final/scaner/internal/vecho"
)

type route struct {
	Domain string
	Action string
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "vecho-scan: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 || (len(args) == 1 && isHelp(args[0])) || (len(args) == 2 && isHelp(args[1])) {
		usage()
		return nil
	}
	rt, err := routeFromArgs(args)
	if err != nil {
		return err
	}
	rest := args[2:]
	switch rt.Domain + "/" + rt.Action {
	case "scan/run":
		return runScan(ctx, rest)
	case "scan/resume":
		return runResume(ctx, rest, false)
	case "scan/export":
		return runExport(rest, false)
	case "rescan/run":
		return runRescan(ctx, rest)
	case "rescan/resume":
		return runResume(ctx, rest, true)
	case "rescan/export":
		return runExport(rest, true)
	default:
		usage()
		return fmt.Errorf("unknown command %s/%s", rt.Domain, rt.Action)
	}
}

func routeFromArgs(args []string) (route, error) {
	if len(args) < 2 {
		usage()
		return route{}, errors.New("usage: vecho-scan <scan|rescan> <run|resume|export>")
	}
	domain := strings.ToLower(strings.TrimSpace(args[0]))
	action := strings.ToLower(strings.TrimSpace(args[1]))
	if domain != "scan" && domain != "rescan" {
		return route{}, fmt.Errorf("unknown domain %q", args[0])
	}
	switch action {
	case "run", "resume", "export":
		return route{Domain: domain, Action: action}, nil
	default:
		return route{}, fmt.Errorf("unknown action %q", args[1])
	}
}

func isHelp(value string) bool {
	return value == "help" || value == "-h" || value == "--help"
}

func runScan(ctx context.Context, args []string) error {
	cfg := config.Default()
	cfg.Mode = "scan"
	cfg.VechoSourceScanner = vecho.DefaultSourceScanner
	fs := flag.NewFlagSet("scan run", flag.ContinueOnError)
	bindRunFlags(fs, &cfg)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := cfg.Normalize(); err != nil {
		return err
	}
	return app.RunScan(ctx, cfg)
}

func runRescan(ctx context.Context, args []string) error {
	cfg := config.Default()
	cfg.Mode = rescan.Mode
	cfg.VechoSourceScanner = rescan.SourceScanner
	fs := flag.NewFlagSet("rescan run", flag.ContinueOnError)
	bindRunFlags(fs, &cfg)
	fs.StringVar(&cfg.RescanBundlePath, "bundle", "", "rescan bundle JSON path")
	fs.StringVar(&cfg.RescanGuidancePath, "guidance", "", "rescan guidance path: markdown, JSON record, JSON list, or {guidance:[]}")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return app.RunRescan(ctx, cfg)
}

func runResume(ctx context.Context, args []string, isRescan bool) error {
	cfg := config.Default()
	fs := flag.NewFlagSet("resume", flag.ContinueOnError)
	fs.StringVar(&cfg.ResumeSessionDir, "session", "", "session output directory to resume")
	timeout := fs.Duration("timeout", cfg.Timeout, "per HTTP attempt/tool operation timeout; up to 3 transient HTTP attempts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.Timeout = *timeout
	if strings.TrimSpace(cfg.ResumeSessionDir) == "" {
		return errors.New("--session is required")
	}
	if isRescan {
		return app.ResumeRescan(ctx, cfg)
	}
	return app.Resume(ctx, cfg)
}

func runExport(args []string, isRescan bool) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	var sessionDir string
	mode := "scan"
	source := vecho.DefaultSourceScanner
	if isRescan {
		mode = rescan.Mode
		source = rescan.SourceScanner
	}
	opts := vecho.Options{SourceScanner: source, ScannerVersion: vecho.DefaultScannerVersion, Mode: mode}
	fs.StringVar(&sessionDir, "session", "", "session output directory to export")
	fs.StringVar(&opts.OutDir, "out", "", "optional vEcho report output directory")
	fs.StringVar(&opts.ProjectID, "project-id", "", "project id for vEcho report metadata")
	fs.StringVar(&opts.ProjectName, "project-name", "", "project name for vEcho report metadata")
	fs.StringVar(&opts.ProjectVersion, "project-version", "", "project version for vEcho report metadata")
	fs.StringVar(&opts.Technology, "technology", "", "technology label for vEcho report metadata")
	fs.StringVar(&opts.ScannerVersion, "scanner-version", opts.ScannerVersion, "scanner version for vEcho report metadata")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(sessionDir) == "" {
		return errors.New("--session is required")
	}
	summary, err := vecho.ExportSession(sessionDir, opts)
	if err != nil {
		return err
	}
	fmt.Printf("vecho_report=%s vulnerabilities=%d rejected_cases=%d\n", summary.ReportPath, summary.VulnerabilityCount, summary.RejectedCaseCount)
	return nil
}

func bindRunFlags(fs *flag.FlagSet, cfg *config.Config) {
	fs.StringVar(&cfg.RepoPath, "repo", "", "target repository path")
	fs.StringVar(&cfg.OutDir, "out", "", "session output directory")
	fs.StringVar(&cfg.LanguageHint, "language", "", "optional language hint")
	fs.StringVar(&cfg.Format, "format", cfg.Format, "stdout format: ndjson or json")
	fs.StringVar(&cfg.Model, "model", cfg.Model, "LLM model id")
	fs.StringVar(&cfg.BaseURL, "base-url", cfg.BaseURL, "chat completions endpoint")
	fs.IntVar(&cfg.MaxTurnsPerBlock, "max-turns-per-block", cfg.MaxTurnsPerBlock, "maximum LLM turns per scan block")
	fs.IntVar(&cfg.MaxFilesPerBlock, "max-files-per-block", cfg.MaxFilesPerBlock, "per-block file budget hint for model-assisted scanning")
	fs.IntVar(&cfg.MaxContextCases, "max-context-cases", cfg.MaxContextCases, "maximum seeds to expand with contextaudit; 0 means all")
	fs.IntVar(&cfg.ContextConcurrency, "context-concurrency", cfg.ContextConcurrency, "maximum contextaudit cases to run concurrently")
	fs.IntVar(&cfg.MaxContextStepsPerCase, "max-context-steps-per-case", cfg.MaxContextStepsPerCase, "maximum contextaudit chain steps per seed")
	fs.IntVar(&cfg.MaxContextTurnsPerStep, "max-context-turns-per-step", cfg.MaxContextTurnsPerStep, "maximum LLM turns per contextaudit step")
	fs.IntVar(&cfg.MaxContextToolCallsPerCase, "max-context-tool-calls-per-case", cfg.MaxContextToolCallsPerCase, "maximum contextaudit tool calls per seed")
	fs.BoolVar(&cfg.VechoReport, "vecho-report", cfg.VechoReport, "export vEcho judge-compatible report")
	fs.StringVar(&cfg.VechoOut, "vecho-out", cfg.VechoOut, "optional vEcho report output directory")
	fs.StringVar(&cfg.ProjectID, "project-id", cfg.ProjectID, "project id for vEcho report metadata")
	fs.StringVar(&cfg.ProjectName, "project-name", cfg.ProjectName, "project name for vEcho report metadata")
	fs.StringVar(&cfg.ProjectVersion, "project-version", cfg.ProjectVersion, "project version for vEcho report metadata")
	fs.StringVar(&cfg.Technology, "technology", cfg.Technology, "technology label for vEcho report metadata")
	fs.StringVar(&cfg.ScannerVersion, "scanner-version", cfg.ScannerVersion, "scanner version for vEcho report metadata")
	fs.BoolVar(&cfg.AllowMutatingBash, "allow-mutating-bash", false, "allow non read-only Bash commands")
	fs.BoolVar(&cfg.MemoryMCP.Enabled, "memory-enabled", cfg.MemoryMCP.Enabled, "enable memory MCP lookup")
	fs.StringVar(&cfg.MemoryMCP.URL, "memory-url", cfg.MemoryMCP.URL, "memory MCP URL")
	fs.StringVar(&cfg.MemoryMCP.Project, "memory-project", cfg.MemoryMCP.Project, "memory MCP project header")
	fs.IntVar(&cfg.MemoryMCP.TimeoutSeconds, "memory-timeout-seconds", cfg.MemoryMCP.TimeoutSeconds, "memory MCP timeout seconds")
	fs.Var(durationValue{target: &cfg.Timeout}, "timeout", "per HTTP attempt/tool operation timeout; up to 3 transient HTTP attempts")
}

type durationValue struct {
	target *time.Duration
}

func (d durationValue) String() string {
	if d.target == nil {
		return ""
	}
	return d.target.String()
}

func (d durationValue) Set(value string) error {
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	*d.target = parsed
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `vecho-scan runs the vEcho scan and rescan stages.

Usage:
  vecho-scan scan run --repo /path/to/repo [--out runs/session]
  vecho-scan scan resume --session runs/session
  vecho-scan scan export --session runs/session
  vecho-scan rescan run --bundle bundle.json [--guidance guidance.md] [--out runs/session]
  vecho-scan rescan run --repo /path/to/repo --guidance guidance.md [--out runs/session]
  vecho-scan rescan resume --session runs/session
  vecho-scan rescan export --session runs/session

Environment:
  VECHO_SCAN_API_KEY or SILICONFLOW_API_KEY is required for model-assisted scanning.

`)
}
