package contextaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vecho_final/scaner/internal/config"
	"vecho_final/scaner/internal/model"
)

func TestTimeoutIsolationResumeAndSourceValidation(t *testing.T) {
	repo := t.TempDir()
	code := []byte("class A {\n void a(String p) {}\n void b(String p) {}\n}\n")
	if err := os.WriteFile(filepath.Join(repo, "A.java"), code, 0600); err != nil {
		t.Fatal(err)
	}
	var recovering atomic.Bool
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		var input struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
			t.Error(err)
			return
		}
		if !recovering.Load() && strings.Contains(input.Messages[1].Content, `"seed_id": "seed-000001"`) {
			<-req.Context().Done()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"case_status":{"status":"dead_end","reason":"No dangerous flow"}}`}}}})
	}))
	defer server.Close()
	cfg := config.Default()
	cfg.RepoPath = repo
	cfg.OutDir = filepath.Join(t.TempDir(), "session")
	cfg.APIKey = "offline"
	cfg.BaseURL = server.URL
	cfg.ContextConcurrency = 2
	cfg.Timeout = 150 * time.Millisecond
	seeds := []model.Seed{testSourceSeed("seed-000001", 2, "a"), testSourceSeed("seed-000002", 3, "b")}
	store := NewStore(cfg.OutDir)
	first, err := NewRunner(cfg, store, nil).Run(context.Background(), seeds)
	if err != nil {
		t.Fatal(err)
	}
	if first.Failed != 1 || first.ByStatus[StatusDeadEnd] != 1 || first.Total != 2 {
		t.Fatalf("failed case canceled healthy sibling: %+v", first)
	}
	if requests.Load() != 4 {
		t.Fatalf("unexpected requests %d", requests.Load())
	}
	before := map[string][]byte{}
	for _, path := range []string{store.CasePath("case-000002"), store.ResultPath("case-000002"), store.TranscriptPath("case-000002")} {
		before[path], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	recovering.Store(true)
	cfg.ResumeSessionDir = cfg.OutDir
	second, err := NewRunner(cfg, store, nil).Run(context.Background(), seeds)
	if err != nil {
		t.Fatal(err)
	}
	if second.Failed != 0 || second.Reused != 1 || second.ByStatus[StatusDeadEnd] != 2 || requests.Load() != 5 {
		t.Fatalf("resume re-ran complete case: %+v requests=%d", second, requests.Load())
	}
	for path, data := range before {
		after, _ := os.ReadFile(path)
		if !bytes.Equal(data, after) {
			t.Fatalf("checkpoint overwritten: %s", path)
		}
	}
	archived, _ := filepath.Glob(filepath.Join(store.Dir, "attempts/case-000001/*/case.json"))
	if len(archived) != 1 {
		t.Fatalf("failed attempt not preserved: %v", archived)
	}
	if err = os.WriteFile(filepath.Join(repo, "A.java"), append(code, []byte("// changed\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = NewRunner(cfg, store, nil).Run(context.Background(), seeds); err == nil {
		t.Fatal("accepted changed source")
	}
	if requests.Load() != 5 {
		t.Fatal("called model before validating source")
	}
	if err = os.WriteFile(filepath.Join(repo, "A.java"), code, 0600); err != nil {
		t.Fatal(err)
	}
	seeds[0].Title = "different seed"
	if _, err = NewRunner(cfg, store, nil).Run(context.Background(), seeds); err == nil {
		t.Fatal("accepted changed seed")
	}
	if requests.Load() != 5 {
		t.Fatal("called model before validating seed identity")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	cfg.ResumeSessionDir = ""
	cfg.OutDir = filepath.Join(t.TempDir(), "canceled")
	if _, err = NewRunner(cfg, NewStore(cfg.OutDir), nil).Run(canceled, seeds); err == nil {
		t.Fatal("cancellation reported as success")
	}
}
