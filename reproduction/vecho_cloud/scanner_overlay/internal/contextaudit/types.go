package contextaudit

import (
	"time"

	"vecho_final/scaner/internal/llm"
	"vecho_final/scaner/internal/model"
)

type CaseStatus string

const (
	StatusExploring CaseStatus = "exploring"
	StatusConfirmed CaseStatus = "confirmed"
	StatusDeadEnd   CaseStatus = "dead_end"
	StatusBlocked   CaseStatus = "blocked"
	StatusRejected  CaseStatus = "rejected"
	StatusFailed    CaseStatus = "failed"
)

type StepKind string

const (
	StepSource      StepKind = "source"
	StepPropagation StepKind = "propagation"
	StepSink        StepKind = "sink"
	StepSanitizer   StepKind = "sanitizer"
	StepGuard       StepKind = "guard"
)

type ReadWindow struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	SHA256    string `json:"sha256,omitempty"`
}

type Case struct {
	CaseID       string       `json:"case_id"`
	SeedID       string       `json:"seed_id"`
	Seed         model.Seed   `json:"seed"`
	Status       CaseStatus   `json:"status"`
	Reason       string       `json:"reason,omitempty"`
	EntryStepID  string       `json:"entry_step_id,omitempty"`
	Steps        []ChainStep  `json:"steps,omitempty"`
	Facts        []Fact       `json:"facts,omitempty"`
	NextQuestion string       `json:"next_question,omitempty"`
	ReadWindows  []ReadWindow `json:"read_windows,omitempty"`
	ToolCalls    int          `json:"tool_calls,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

type ChainStep struct {
	StepID           string    `json:"step_id"`
	Kind             StepKind  `json:"kind"`
	Symbol           string    `json:"symbol,omitempty"`
	File             string    `json:"file"`
	Line             int       `json:"line"`
	Snippet          string    `json:"snippet,omitempty"`
	Summary          string    `json:"summary,omitempty"`
	RelationFromPrev string    `json:"relation_from_prev,omitempty"`
	ProofSource      string    `json:"proof_source,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

type Fact struct {
	FactID    string         `json:"fact_id"`
	Type      string         `json:"type"`
	Content   map[string]any `json:"content,omitempty"`
	File      string         `json:"file,omitempty"`
	Line      int            `json:"line,omitempty"`
	Snippet   string         `json:"snippet,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

type CaseResult struct {
	CaseID       string         `json:"case_id"`
	SeedID       string         `json:"seed_id"`
	SeedKind     model.SeedKind `json:"seed_kind"`
	Status       CaseStatus     `json:"status"`
	Reason       string         `json:"reason,omitempty"`
	StepCount    int            `json:"step_count"`
	FactCount    int            `json:"fact_count"`
	SourceStepID string         `json:"source_step_id,omitempty"`
	SinkStepID   string         `json:"sink_step_id,omitempty"`
}

type Summary struct {
	Failed     int                `json:"failed_cases,omitempty"`
	Reused     int                `json:"reused_cases,omitempty"`
	UsageScope string             `json:"usage_scope,omitempty"`
	Total      int                `json:"total"`
	ByStatus   map[CaseStatus]int `json:"by_status"`
	Results    []CaseResult       `json:"results"`
	Usage      llm.Usage          `json:"usage,omitempty"`
	StartedAt  time.Time          `json:"started_at"`
	EndedAt    time.Time          `json:"ended_at"`
}

type Proof struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet,omitempty"`
}

type StepDraft struct {
	Kind             StepKind `json:"kind"`
	Symbol           string   `json:"symbol,omitempty"`
	File             string   `json:"file"`
	Line             int      `json:"line"`
	Snippet          string   `json:"snippet,omitempty"`
	Summary          string   `json:"summary,omitempty"`
	RelationFromPrev string   `json:"relation_from_prev,omitempty"`
	Proof            []Proof  `json:"proof,omitempty"`
}

type FactDraft struct {
	Type    string         `json:"type"`
	Content map[string]any `json:"content,omitempty"`
	File    string         `json:"file,omitempty"`
	Line    int            `json:"line,omitempty"`
	Snippet string         `json:"snippet,omitempty"`
	Proof   []Proof        `json:"proof,omitempty"`
}

type StatusUpdate struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type Action struct {
	Thought      string                  `json:"thought,omitempty"`
	ToolCalls    []model.ToolCallRequest `json:"tool_calls,omitempty"`
	PrependSteps []StepDraft             `json:"prepend_steps,omitempty"`
	AppendSteps  []StepDraft             `json:"append_steps,omitempty"`
	Facts        []FactDraft             `json:"facts,omitempty"`
	NextQuestion string                  `json:"next_question,omitempty"`
	CaseStatus   *StatusUpdate           `json:"case_status,omitempty"`
}
