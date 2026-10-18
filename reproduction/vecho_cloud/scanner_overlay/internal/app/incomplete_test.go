package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"vecho_final/scaner/internal/config"
	"vecho_final/scaner/internal/contextaudit"
	"vecho_final/scaner/internal/model"
	"vecho_final/scaner/internal/output"
	"vecho_final/scaner/internal/session"
)

func TestFailedCasesCannotProduceCompletedSessionOrBenchmarkReport(t *testing.T) {
	cfg := config.Default()
	cfg.OutDir = t.TempDir()
	cfg.VechoReport = true
	store := session.NewStore(cfg.OutDir)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	events, err := output.NewEventBus("test", filepath.Join(cfg.OutDir, "events.ndjson"), "ndjson", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	meta := session.Metadata{SessionID: "test", OutDir: cfg.OutDir, Config: cfg}
	err = finishSuccess(store, events, meta, nil, model.Plan{}, contextaudit.Summary{Total: 1, Failed: 1}, session.UsageSummary{})
	if err == nil {
		t.Fatal("incomplete scan counted as success")
	}
	saved, e := session.LoadMetadata(cfg.OutDir)
	if e != nil {
		t.Fatal(e)
	}
	if saved.Status != "incomplete" {
		t.Fatalf("status=%s", saved.Status)
	}
	if _, err = os.Stat(filepath.Join(cfg.OutDir, "vecho/report.json")); !os.IsNotExist(err) {
		t.Fatal("published benchmark report from failed cases")
	}
	if err = RunScan(context.Background(), cfg); err == nil {
		t.Fatal("fresh run overwrote existing session")
	}
}
