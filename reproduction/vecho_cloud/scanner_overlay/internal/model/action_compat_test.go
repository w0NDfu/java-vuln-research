package model

import (
	"encoding/json"
	"testing"
)

func TestToolCallFlatAndNestedArguments(t *testing.T) {
	for _, data := range []string{
		`{"tool":"Grep","pattern":"headers","path":"src/main/java","head_limit":500}`,
		`{"tool":"Grep","args":{"pattern":"headers","path":"src/main/java","head_limit":500}}`,
	} {
		var call ToolCallRequest
		if err := json.Unmarshal([]byte(data), &call); err != nil {
			t.Fatal(err)
		}
		var args map[string]any
		if err := json.Unmarshal(call.Args, &args); err != nil {
			t.Fatal(err)
		}
		if args["pattern"] != "headers" || args["head_limit"] != float64(500) {
			t.Fatalf("lost arguments: %s", call.Args)
		}
	}
}

func TestToolCallRejectsAmbiguousOrMissingArguments(t *testing.T) {
	for _, data := range []string{
		`{"tool":"Read"}`, `{"tool":"Read","args":null}`, `{"tool":"Read","args":"{}"}`,
		`{"tool":"Read","args":{"file_path":"safe"},"file_path":"other"}`,
	} {
		var call ToolCallRequest
		if err := json.Unmarshal([]byte(data), &call); err == nil {
			t.Fatalf("accepted ambiguous or missing arguments: %s", data)
		}
	}
}
