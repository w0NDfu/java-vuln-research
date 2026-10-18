package contextaudit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vecho_final/scaner/internal/session"
)

func TestRealCompletedCheckpointsAreReusableWithoutRequests(t *testing.T) {
	root := os.Getenv("VECHO_CHECKPOINT_REPLAY")
	if root == "" {
		t.Skip("original laboratory sessions supplied only for offline validation")
	}
	counts := map[string]int{}
	for _, sample := range []string{"sample_0001", "sample_0002", "sample_0003"} {
		matches, err := filepath.Glob(filepath.Join(root, "*", sample, "scan/session.json"))
		if err != nil || len(matches) != 1 {
			t.Fatalf("session selection %s: %v %v", sample, matches, err)
		}
		dir := filepath.Dir(matches[0])
		meta, err := session.LoadMetadata(dir)
		if err != nil {
			t.Fatal(err)
		}
		seeds, err := session.NewStore(dir).LoadSeeds()
		if err != nil {
			t.Fatal(err)
		}
		r := NewRunner(meta.Config, NewStore(dir), nil)
		for i, seed := range sortedSeeds(seeds) {
			result, ok, err := r.reusableCheckpoint(i+1, seed)
			if err != nil {
				t.Fatalf("%s seed %s: %v", sample, seed.ID, err)
			}
			if ok {
				counts[sample]++
				original, err := os.ReadFile(r.Store.ResultPath(result.CaseID))
				if err != nil {
					t.Fatal(err)
				}
				var before CaseResult
				if err = json.Unmarshal(original, &before); err != nil {
					t.Fatal(err)
				}
				if before != result {
					t.Fatal("reused verdict changed")
				}
			}
		}
	}
	for sample, want := range map[string]int{"sample_0001": 35, "sample_0002": 10, "sample_0003": 12} {
		if counts[sample] != want {
			t.Fatalf("%s reusable=%d want=%d", sample, counts[sample], want)
		}
	}
	t.Logf("Validated original completed checkpoints without API requests: %v", counts)
}
