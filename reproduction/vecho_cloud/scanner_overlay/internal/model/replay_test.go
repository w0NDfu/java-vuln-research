package model

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRealFailedToolCallsReplay(t *testing.T) {
	path := os.Getenv("VECHO_TOOL_REPLAY")
	if path == "" {
		t.Skip("real failure fixture supplied only in laboratory validation")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var calls []json.RawMessage
	if err = json.Unmarshal(data, &calls); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 12 {
		t.Fatalf("expected twelve observed missing-args calls, got %d", len(calls))
	}
	for _, raw := range calls {
		var call ToolCallRequest
		if err = json.Unmarshal(raw, &call); err != nil {
			t.Fatal(err)
		}
		var params map[string]any
		if err = json.Unmarshal(call.Args, &params); err != nil || len(params) == 0 {
			t.Fatalf("unusable arguments: %s %v", raw, err)
		}
	}
}
