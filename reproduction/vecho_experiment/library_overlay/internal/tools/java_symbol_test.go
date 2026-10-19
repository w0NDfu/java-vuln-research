package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"vecho_final/scaner/internal/model"
)

func TestFindJavaSymbolSkipsCommentsAndFindsLateOverloads(t *testing.T) {
	dir := t.TempDir()
	source := "class A {\n" + strings.Repeat("// sanitize() is safe\n", 510) + " public String sanitize(String x) { return x; }\n private String sanitize(int n) { return String.valueOf(n); }\n void use() { sanitize(1); String x = \"sanitize()\"; }\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "A.java"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry(false)
	res, err := r.Call(context.Background(), model.ToolCallRequest{Tool: "FindJavaSymbol", Args: json.RawMessage(`{"file_path":"A.java","symbol":"sanitize"}`)}, ToolContext{RepoRoot: dir})
	if err != nil {
		t.Fatal(err)
	}
	out := res.Data.(JavaSymbolOutput)
	if out.Total != 3 || len(out.Matches) != 3 || out.Matches[0].Line != 512 || !out.Matches[0].Declaration {
		t.Fatalf("bad symbol lookup %+v", out)
	}
}
func TestFindJavaSymbolRejectsEscapeAndInvalidIdentifier(t *testing.T) {
	dir := t.TempDir()
	tool := FindJavaSymbolTool{}
	for _, args := range []string{`{"file_path":"../A.java","symbol":"sanitize"}`, `{"file_path":"A.java","symbol":".*"}`} {
		if err := tool.Validate(context.Background(), json.RawMessage(args), ToolContext{RepoRoot: dir}); err == nil {
			t.Fatal("unsafe input accepted")
		}
	}
}

func TestFindJavaSymbolResolvesScopeAndSupportsDollarNames(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Other.java"), []byte("class A { public void $clean() {} }"), 0600); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry(false)
	res, err := r.Call(context.Background(), model.ToolCallRequest{Tool: "FindJavaSymbol", Args: json.RawMessage(`{"file_path":"Other.java","symbol":"$clean"}`)}, ToolContext{RepoRoot: dir})
	if err != nil || res.Data.(JavaSymbolOutput).Total != 1 {
		t.Fatalf("dollar-name lookup: %v %+v", err, res)
	}
	if err := os.Symlink("Other.java", filepath.Join(dir, "Allowed.java")); err != nil {
		t.Skip("symlink unavailable")
	}
	_, err = r.Call(context.Background(), model.ToolCallRequest{Tool: "FindJavaSymbol", Args: json.RawMessage(`{"file_path":"Allowed.java","symbol":"$clean"}`)}, ToolContext{RepoRoot: dir, ActiveBlock: &model.ScanBlock{Scope: model.Scope{Paths: []string{"Allowed.java"}}}})
	if err == nil {
		t.Fatal("resolved target escaped active scan scope")
	}
}
