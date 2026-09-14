// Package buildinfo exposes only deliberately selected build identity fields.
package buildinfo

import (
	"fmt"
	"io"
	"runtime"
	"strings"
)

// Official builds inject these values; local builds never claim workflow provenance.
var Commit = "unknown"
var Date = "unknown"
var BuiltBy = "development"

const Source = "github.com/Kevin-Umali/repyy"

func value(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}

// Write prints diagnostic identity. These labels are not a substitute for attestation verification.
func Write(w io.Writer, version, rules string) {
	fmt.Fprintf(w, "repyy %s\ncommit: %s\nbuilt-by: %s\nsource: %s\ngo: %s\nbuild-date: %s\nrules: %s\n", value(version), value(Commit), value(BuiltBy), Source, runtime.Version(), value(Date), rules)
}
