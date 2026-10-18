package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestGatewayTimeoutRetryReceivesFreshAttemptDeadline(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(60 * time.Millisecond)
		if n == 1 {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"ok\":true}"},"finish_reason":"stop"}]}`))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "calls.ndjson")
	c := &Client{APIKey: "offline", Model: "offline", BaseURL: server.URL, AttemptTimeout: 150 * time.Millisecond, DiagnosticPath: path}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := c.ChatWithUsage(ctx, nil)
	if err != nil || result.Content != `{"ok":true}` || requests.Load() != 2 {
		t.Fatalf("gateway retry failed: %+v %v requests=%d", result, err, requests.Load())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d CallDiagnostic
	if err = json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.AttemptDetails) != 2 || d.AttemptDetails[0].HTTPStatus != 504 || d.AttemptDetails[1].HTTPStatus != 200 || d.ErrorClass != "" {
		t.Fatalf("lost per-attempt evidence: %+v", d)
	}
}

func TestExhaustedAttemptDeadlineCanRetryButCallerCancellationCannot(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		if n == 1 {
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}]}`))
	}))
	defer server.Close()
	c := &Client{APIKey: "offline", Model: "offline", BaseURL: server.URL, AttemptTimeout: 100 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := c.ChatWithUsage(ctx, nil); err != nil || requests.Load() != 2 {
		t.Fatalf("per-attempt timeout not retried: %v requests=%d", err, requests.Load())
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := c.ChatWithUsage(canceled, nil); err == nil || requests.Load() != 2 {
		t.Fatal("canceled caller still made request")
	}
}

func TestPermanentAuthenticationErrorIsNotRetried(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusUnauthorized) }))
	defer server.Close()
	c := &Client{APIKey: "offline", Model: "offline", BaseURL: server.URL, AttemptTimeout: time.Second}
	if _, err := c.ChatWithUsage(context.Background(), nil); err == nil || requests.Load() != 1 {
		t.Fatal("authentication failure was retried or ignored")
	}
}

func TestGatewayFailuresStopAfterThreeAttempts(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer server.Close()
	c := &Client{APIKey: "offline", Model: "offline", BaseURL: server.URL, AttemptTimeout: time.Second}
	if _, err := c.ChatWithUsage(context.Background(), nil); err == nil || requests.Load() != 3 {
		t.Fatalf("retry bound lost: %v requests=%d", err, requests.Load())
	}
}
