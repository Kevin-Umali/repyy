package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func FuzzHumanOutput(f *testing.F) {
	f.Add("\x1b[2J<script>alert(1)</script>")
	f.Add("name\u202e.txt")
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			t.Skip()
		}
		report := sampleReport()
		report.Results[0].Target = value
		report.Results[0].Findings[0].Path = value
		report.Results[0].Findings[0].Message = value + `<script id="repyy-fuzz-injection">`
		var terminal, html bytes.Buffer
		if err := Write(&terminal, "terminal", report); err != nil {
			t.Fatal(err)
		}
		for _, r := range terminal.String() {
			if unicode.IsControl(r) && r != '\n' && r != '\t' {
				t.Fatalf("terminal control U+%04X", r)
			}
		}
		if err := Write(&html, "html", report); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(html.String(), `<script id="repyy-fuzz-injection">`) {
			t.Fatal("repository markup became active HTML")
		}
	})
}

func FuzzJSONReports(f *testing.F) {
	seed, _ := json.Marshal(sampleReport())
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16384 {
			t.Skip()
		}
		var report model.Report
		if json.Unmarshal(data, &report) != nil {
			return
		}
		var out bytes.Buffer
		if err := Write(&out, "json", report); err != nil {
			t.Fatal(err)
		}
		if !json.Valid(out.Bytes()) {
			t.Fatal("renderer emitted invalid JSON")
		}
	})
}
