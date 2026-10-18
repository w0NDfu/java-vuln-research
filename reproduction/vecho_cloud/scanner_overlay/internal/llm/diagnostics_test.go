package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeadlineIsBoundedAndDiagnosticsDoNotExposePayload(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "calls.ndjson")
	c := &Client{BaseURL: server.URL, APIKey: "secret-test-key", Model: "offline", DiagnosticPath: path}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := c.ChatWithUsage(ctx, []Message{{Role: "user", Content: "private source code"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost timeout cause: %v", err)
	}
	if time.Since(started) > time.Second || requests.Load() != 1 {
		t.Fatalf("retried after deadline: %d", requests.Load())
	}
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(data), "secret-test-key") || strings.Contains(string(data), "private source") {
		t.Fatal("sensitive request logged")
	}
	var d CallDiagnostic
	if e = json.Unmarshal(data, &d); e != nil {
		t.Fatal(e)
	}
	if d.ErrorClass != "timeout" || d.Attempts != 1 || d.UsageKnown {
		t.Fatalf("misleading diagnostics: %+v", d)
	}
}

func TestTruncatedResponseIsNotAcceptedAsACompletedAction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"length","message":{"content":"{incomplete"}}],"usage":{"prompt_tokens":2,"completion_tokens":8,"total_tokens":10,"completion_tokens_details":{"reasoning_tokens":6}}}`))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "calls.ndjson")
	c := &Client{BaseURL: server.URL, APIKey: "offline", Model: "offline", DiagnosticPath: path}
	result, err := c.ChatWithUsage(context.Background(), nil)
	if err == nil || result.FinishReason != "length" || result.Usage.ReasoningTokens != 6 {
		t.Fatalf("truncation/usage lost: %+v %v", result, err)
	}
	data, _ := os.ReadFile(path)
	var d CallDiagnostic
	_ = json.Unmarshal(data, &d)
	if !d.UsageKnown || d.FinishReason != "length" || d.HTTPStatus != 200 {
		t.Fatalf("missing response metadata: %+v", d)
	}
}
