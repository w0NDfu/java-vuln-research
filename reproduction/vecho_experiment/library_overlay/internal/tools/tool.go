package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"vecho_final/scaner/internal/model"
)

type Tool interface {
	Name() string
	Description() string
	Validate(ctx context.Context, raw json.RawMessage, tc ToolContext) error
	Call(ctx context.Context, raw json.RawMessage, tc ToolContext) (ToolResult, error)
	IsReadOnly() bool
	IsConcurrencySafe() bool
	MaxResultBytes() int
}

type ToolContext struct {
	RepoRoot          string
	ActiveBlock       *model.ScanBlock
	AllowMutatingBash bool
	Timeout           time.Duration
}

type ToolResult struct {
	Tool        string      `json:"tool"`
	Input       interface{} `json:"input,omitempty"`
	Data        interface{} `json:"data,omitempty"`
	DisplayText string      `json:"display_text,omitempty"`
	Truncated   bool        `json:"truncated,omitempty"`
	Error       string      `json:"error,omitempty"`
	StartedAt   time.Time   `json:"started_at"`
	DurationMS  int64       `json:"duration_ms"`
}

type Registry struct {
	tools map[string]Tool
}

func NewRegistry(allowMutatingBash bool) *Registry {
	_ = allowMutatingBash
	r := &Registry{tools: map[string]Tool{}}
	r.Register(BashTool{})
	r.Register(GlobTool{})
	r.Register(GrepTool{})
	r.Register(ReadTool{})
	r.Register(FindJavaSymbolTool{})
	return r
}

func (r *Registry) Register(tool Tool) {
	r.tools[strings.ToLower(tool.Name())] = tool
}

func (r *Registry) Get(name string) (Tool, bool) {
	tool, ok := r.tools[strings.ToLower(name)]
	return tool, ok
}

func (r *Registry) Call(ctx context.Context, call model.ToolCallRequest, tc ToolContext) (ToolResult, error) {
	tool, ok := r.Get(call.Tool)
	if !ok {
		return ToolResult{Tool: call.Tool, Error: "unknown tool"}, fmt.Errorf("unknown tool %q", call.Tool)
	}
	if err := tool.Validate(ctx, call.Args, tc); err != nil {
		return ToolResult{Tool: tool.Name(), Error: err.Error()}, err
	}
	start := time.Now().UTC()
	result, err := tool.Call(ctx, call.Args, tc)
	result.Tool = tool.Name()
	result.StartedAt = start
	result.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = err.Error()
	}
	if tool.MaxResultBytes() > 0 && len(result.DisplayText) > tool.MaxResultBytes() {
		result.DisplayText = result.DisplayText[:tool.MaxResultBytes()] + "\n[truncated]"
		result.Truncated = true
	}
	return result, err
}

func cleanRepoPath(repoRoot, candidate string) (string, string, error) {
	if strings.TrimSpace(candidate) == "" {
		candidate = repoRoot
	}
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(repoRoot, candidate)
	}
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return "", "", err
	}
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", "", err
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("path escapes repo root: %s", candidate)
	}
	if rel == "." {
		rel = ""
	}
	return abs, filepath.ToSlash(rel), nil
}

func scopeAllowsPath(block *model.ScanBlock, relPath string) bool {
	if block == nil {
		return true
	}
	if len(block.Scope.Paths) == 0 && len(block.Scope.Globs) == 0 {
		return true
	}
	relPath = filepath.ToSlash(strings.TrimPrefix(relPath, "./"))
	for _, p := range block.Scope.Paths {
		p = filepath.ToSlash(strings.TrimPrefix(strings.TrimSpace(p), "./"))
		p = strings.TrimSuffix(p, "/...")
		if p == "" || relPath == p || strings.HasPrefix(relPath, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	for _, g := range block.Scope.Globs {
		ok, _ := matchGlob(g, relPath)
		if ok {
			return true
		}
	}
	return false
}

func ignoredDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", ".jj", "node_modules", "vendor", "third_party", "target", "build", "dist", "out", ".gradle", ".idea", ".vscode", "coverage", ".next":
		return true
	default:
		return false
	}
}
