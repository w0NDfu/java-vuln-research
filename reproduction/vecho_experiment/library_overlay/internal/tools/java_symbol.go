package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type FindJavaSymbolTool struct{}
type JavaSymbolInput struct {
	FilePath string `json:"file_path"`
	Symbol   string `json:"symbol"`
	Offset   int    `json:"offset,omitempty"`
}
type JavaSymbolMatch struct {
	Line        int    `json:"line"`
	Declaration bool   `json:"declaration_candidate"`
	Snippet     string `json:"snippet"`
}
type JavaSymbolOutput struct {
	File       string            `json:"file"`
	Matches    []JavaSymbolMatch `json:"matches"`
	Total      int               `json:"total"`
	NextOffset int               `json:"next_offset"`
	Note       string            `json:"note"`
}

func (FindJavaSymbolTool) Name() string { return "FindJavaSymbol" }
func (FindJavaSymbolTool) Description() string {
	return "Find exact Java method occurrences while excluding comments/string literals. Prioritize declaration candidates; Read returned lines for proof."
}
func (FindJavaSymbolTool) IsReadOnly() bool        { return true }
func (FindJavaSymbolTool) IsConcurrencySafe() bool { return true }
func (FindJavaSymbolTool) MaxResultBytes() int     { return 20000 }
func (FindJavaSymbolTool) Validate(ctx context.Context, raw json.RawMessage, tc ToolContext) error {
	var in JavaSymbolInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`).MatchString(in.Symbol) || in.Offset < 0 {
		return fmt.Errorf("symbol must be an exact Java identifier; offset must be nonnegative")
	}
	if !strings.HasSuffix(in.FilePath, ".java") {
		return fmt.Errorf("file_path must name a Java source file")
	}
	abs, rel, err := cleanRepoPath(tc.RepoRoot, in.FilePath)
	if err != nil {
		return err
	}
	if !scopeAllowsPath(tc.ActiveBlock, rel) {
		return fmt.Errorf("file is outside scan scope")
	}
	// Enforce regular-file, resolved repository and scan-scope boundaries.
	_, resolvedRel, err := cleanSymbolPath(tc.RepoRoot, abs)
	if err == nil && !scopeAllowsPath(tc.ActiveBlock, resolvedRel) {
		return fmt.Errorf("resolved symbol file is outside scan scope")
	}
	return err
}

func cleanSymbolPath(root, name string) (string, string, error) {
	// Resolve links before enforcing the repository boundary.
	abs, _, err := cleanRepoPath(root, name)
	if err != nil {
		return "", "", err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return "", "", err
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", "", err
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("expected regular Java source")
	}
	return cleanRepoPath(realRoot, abs)
}

func (FindJavaSymbolTool) Call(ctx context.Context, raw json.RawMessage, tc ToolContext) (ToolResult, error) {
	var in JavaSymbolInput
	_ = json.Unmarshal(raw, &in)
	abs, rel, err := cleanSymbolPath(tc.RepoRoot, in.FilePath)
	if err != nil {
		return ToolResult{}, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return ToolResult{}, err
	}
	clean := javaCodeOnly(data)
	rx := regexp.MustCompile(`(?:^|[^A-Za-z0-9_$])(` + regexp.QuoteMeta(in.Symbol) + `)\s*\(`)
	all := []JavaSymbolMatch{}
	for _, found := range rx.FindAllSubmatchIndex(clean, -1) {
		m := found[2:4]
		if err := ctx.Err(); err != nil {
			return ToolResult{}, err
		}
		line := 1 + strings.Count(string(clean[:m[0]]), "\n")
		prefix := string(clean[:m[0]])
		start := strings.LastIndexAny(prefix, ";{}\n") + 1
		before := strings.TrimSpace(prefix[start:])
		decl := before != "" && !strings.ContainsAny(before, "=.()")
		for _, word := range []string{"return ", "throw ", "new ", "if ", "while ", "case "} {
			if strings.Contains(before, word) {
				decl = false
			}
		}
		lines := splitLines(data)
		snippet := lines[line-1]
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		all = append(all, JavaSymbolMatch{Line: line, Declaration: decl, Snippet: snippet})
	}
	// Declaration candidates precede calls; order within each group is source order.
	ordered := make([]JavaSymbolMatch, 0, len(all))
	for _, d := range []bool{true, false} {
		for _, m := range all {
			if m.Declaration == d {
				ordered = append(ordered, m)
			}
		}
	}
	start := min(in.Offset, len(ordered))
	end := min(start+20, len(ordered))
	next := -1
	if end < len(ordered) {
		next = end
	}
	out := JavaSymbolOutput{File: rel, Matches: ordered[start:end], Total: len(all), NextOffset: next, Note: "Lexical navigation candidates only, not semantic or safety proof. Use Read at the returned line; method signatures may span lines."}
	encoded, _ := json.Marshal(out)
	return ToolResult{Input: in, Data: out, DisplayText: string(encoded), Truncated: next >= 0}, nil
}

// Preserve byte offsets and newlines while masking Java comments/literals.
func javaCodeOnly(data []byte) []byte {
	b := append([]byte(nil), data...)
	state := byte(0)
	for i := 0; i < len(b); i++ {
		c := data[i]
		next := byte(0)
		if i+1 < len(b) {
			next = data[i+1]
		}
		if state == 0 {
			if c == '/' && (next == '/' || next == '*') {
				state = next
				b[i] = ' '
				i++
				b[i] = ' '
				continue
			}
			if c == '"' || c == '\'' {
				state = c
				b[i] = ' '
			}
			continue
		}
		if state == '/' {
			if c == '\n' {
				state = 0
			} else {
				b[i] = ' '
			}
			continue
		}
		if state == '*' {
			if c != '\n' {
				b[i] = ' '
			}
			if c == '*' && next == '/' {
				i++
				b[i] = ' '
				state = 0
			}
			continue
		}
		if c != '\n' {
			b[i] = ' '
		}
		if c == '\\' && i+1 < len(b) {
			i++
			if data[i] != '\n' {
				b[i] = ' '
			}
			continue
		}
		if c == state {
			state = 0
		}
	}
	return b
}
