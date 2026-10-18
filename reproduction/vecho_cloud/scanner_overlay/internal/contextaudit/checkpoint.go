package contextaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"vecho_final/scaner/internal/model"
)

func (r *Runner) reusableCheckpoint(index int, seed model.Seed) (CaseResult, bool, error) {
	id := fmt.Sprintf("case-%06d", index)
	var c Case
	data, err := os.ReadFile(r.Store.CasePath(id))
	if errors.Is(err, os.ErrNotExist) {
		return CaseResult{}, false, nil
	}
	if err != nil {
		return CaseResult{}, false, err
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return CaseResult{}, false, err
	}
	if c.CaseID != id || c.SeedID != seed.ID || !reflect.DeepEqual(c.Seed, seed) {
		return CaseResult{}, false, fmt.Errorf("checkpoint seed identity mismatch for %s; original preserved", id)
	}
	_, result, err := r.Store.LoadCheckpoint(id)
	if errors.Is(err, os.ErrNotExist) {
		return CaseResult{}, false, nil
	}
	if err != nil {
		return result, false, err
	}
	if result.Status == StatusFailed {
		return result, false, nil
	}
	if result.Status != StatusConfirmed && result.Status != StatusDeadEnd && result.Status != StatusBlocked && result.Status != StatusRejected {
		return result, false, nil
	}
	if result.CaseID != id || result.SeedID != seed.ID || result.Status != c.Status {
		return result, false, fmt.Errorf("checkpoint result identity/status mismatch for %s", id)
	}
	for _, window := range c.ReadWindows {
		target := filepath.Join(r.Config.RepoPath, filepath.FromSlash(window.File))
		absolute, e := filepath.EvalSymlinks(target)
		if e != nil {
			return result, false, e
		}
		repo, e := filepath.EvalSymlinks(r.Config.RepoPath)
		if e != nil {
			return result, false, e
		}
		rel, e := filepath.Rel(repo, absolute)
		if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return result, false, fmt.Errorf("checkpoint file escapes repository")
		}
		bytes, e := os.ReadFile(absolute)
		if e != nil {
			return result, false, e
		}
		hash := sha256.Sum256(bytes)
		if window.SHA256 == "" || hex.EncodeToString(hash[:]) != window.SHA256 {
			return result, false, fmt.Errorf("checkpoint source changed for %s; refusing reuse", id)
		}
	}
	return result, true, nil
}
