package contextaudit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vecho_final/scaner/internal/model"
	"vecho_final/scaner/internal/output"
	"vecho_final/scaner/internal/tools"
)

type Store struct {
	Dir         string
	CasesDir    string
	EventsPath  string
	ResultsPath string
	mu          sync.Mutex
}

func NewStore(outDir string) *Store {
	dir := filepath.Join(outDir, "contextaudit")
	return &Store{
		Dir:         dir,
		CasesDir:    filepath.Join(dir, "cases"),
		EventsPath:  filepath.Join(dir, "events.ndjson"),
		ResultsPath: filepath.Join(dir, "results.json"),
	}
}

func (s *Store) Init() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.CasesDir, 0o700); err != nil {
		return err
	}
	return nil
}

func (s *Store) CaseDir(caseID string) string {
	return filepath.Join(s.CasesDir, safeName(caseID))
}

func (s *Store) CasePath(caseID string) string {
	return filepath.Join(s.CaseDir(caseID), "case.json")
}

func (s *Store) ResultPath(caseID string) string {
	return filepath.Join(s.CaseDir(caseID), "result.json")
}

func (s *Store) TranscriptPath(caseID string) string {
	return filepath.Join(s.CaseDir(caseID), "transcript.jsonl")
}

func (s *Store) ToolResultDir(caseID string) string {
	return filepath.Join(s.CaseDir(caseID), "tool-results")
}

func (s *Store) ToolResultPath(caseID string, index int, tool string) string {
	name := fmt.Sprintf("%06d-%s.json", index, safeName(tool))
	return filepath.Join(s.ToolResultDir(caseID), name)
}

func (s *Store) InitCase(caseID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.ToolResultDir(caseID), 0o700); err != nil {
		return err
	}
	return nil
}

// Failed attempts are moved inside the session before starting that case again.
// Completed checkpoints are read, never truncated or rewritten.
func (s *Store) ArchiveCase(caseID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	source := s.CaseDir(caseID)
	if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	archive := filepath.Join(s.Dir, "attempts", safeName(caseID))
	if err := os.MkdirAll(archive, 0700); err != nil {
		return err
	}
	return os.Rename(source, filepath.Join(archive, time.Now().UTC().Format("20060102T150405.000000000")))
}

func (s *Store) LoadCheckpoint(caseID string) (Case, CaseResult, error) {
	var c Case
	var result CaseResult
	data, err := os.ReadFile(s.CasePath(caseID))
	if err != nil {
		return c, result, err
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return c, result, err
	}
	data, err = os.ReadFile(s.ResultPath(caseID))
	if err != nil {
		return c, result, err
	}
	err = json.Unmarshal(data, &result)
	return c, result, err
}

func (s *Store) SaveCase(c Case) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.CaseDir(c.CaseID), 0o700); err != nil {
		return err
	}
	return output.WriteJSON(s.CasePath(c.CaseID), c)
}

func (s *Store) SaveResult(result CaseResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return output.WriteJSON(s.ResultPath(result.CaseID), result)
}

func (s *Store) SaveSummary(summary Summary) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return output.WriteJSON(s.ResultsPath, summary)
}

func (s *Store) AppendTranscript(caseID string, value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return output.AppendNDJSON(s.TranscriptPath(caseID), value)
}

func (s *Store) SaveToolResult(caseID string, index int, result tools.ToolResult) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.ToolResultPath(caseID, index, result.Tool)
	return path, output.WriteJSON(path, result)
}

func (s *Store) Emit(event model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return output.AppendNDJSON(s.EventsPath, event)
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "item"
	}
	return b.String()
}
