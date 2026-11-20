package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func TestConcurrentExportsPreserveFirstReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "review.json")
	reports := []model.Report{
		{SchemaVersion: "1", ToolVersion: "first"},
		{SchemaVersion: "1", ToolVersion: "second"},
	}
	var wg sync.WaitGroup
	var results [2]error
	for i, report := range reports {
		wg.Go(func() { results[i] = exportReport(report, "json", path) })
	}
	wg.Wait()

	winner := -1
	for i, err := range results {
		switch {
		case err == nil && winner < 0:
			winner = i
		case errors.Is(err, os.ErrExist):
		default:
			t.Fatalf("unexpected export result %d: %v", i, err)
		}
	}
	if winner < 0 {
		t.Fatal("both exports failed")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved model.Report
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.ToolVersion != reports[winner].ToolVersion {
		t.Fatalf("saved version %q, want successful export %q", saved.ToolVersion, reports[winner].ToolVersion)
	}
}
