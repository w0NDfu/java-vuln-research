package model

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type ToolCallRequest struct {
	ID   string          `json:"id,omitempty"`
	Tool string          `json:"tool"`
	Args json.RawMessage `json:"args"`
}

// Accept the observed flat argument form, but never merge conflicting forms.
func (c *ToolCallRequest) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil {
		return fmt.Errorf("tool call must be an object")
	}
	*c = ToolCallRequest{}
	if raw, ok := fields["tool"]; ok {
		if err := json.Unmarshal(raw, &c.Tool); err != nil {
			return err
		}
	}
	if c.Tool == "" {
		return fmt.Errorf("tool name is required")
	}
	if raw, ok := fields["id"]; ok {
		if err := json.Unmarshal(raw, &c.ID); err != nil {
			return err
		}
	}
	raw, nested := fields["args"]
	delete(fields, "tool")
	delete(fields, "id")
	delete(fields, "args")
	if nested {
		if len(fields) > 0 {
			return fmt.Errorf("tool call mixes args with top-level parameters")
		}
	} else {
		if len(fields) == 0 {
			return fmt.Errorf("tool arguments are missing")
		}
		var err error
		raw, err = json.Marshal(fields)
		if err != nil {
			return err
		}
	}
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return fmt.Errorf("tool args must be an object")
	}
	c.Args = append(json.RawMessage(nil), raw...)
	return nil
}

type BlockUpdate struct {
	Status                   BlockStatus `json:"status"`
	Summary                  string      `json:"summary,omitempty"`
	SkippedReason            string      `json:"skipped_reason,omitempty"`
	StaticAnalysisHypothesis string      `json:"static_analysis_hypothesis,omitempty"`
}

type ActionEnvelope struct {
	Thought           string            `json:"thought,omitempty"`
	ToolCalls         []ToolCallRequest `json:"tool_calls,omitempty"`
	EmitSeeds         []Seed            `json:"emit_seed,omitempty"`
	UpdateBlockStatus *BlockUpdate      `json:"update_block_status,omitempty"`
	Finalize          bool              `json:"finalize,omitempty"`
}
