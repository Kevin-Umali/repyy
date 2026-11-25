package scan

import (
	"bytes"
	"regexp/syntax"
	"strings"
)

// screen holds what a rule's pattern guarantees about any text it matches, so a file
// or line that cannot match is skipped without running the regular expression. The
// zero value admits everything.
type screen struct {
	// literals are lowercase ASCII strings of which every match contains one. Nil
	// means no such set was proven.
	literals [][]byte
	minWidth int
	nonASCII bool
}

// minScreenLiteral keeps a one-letter literal from admitting nearly every line while
// still costing a Contains pass.
const minScreenLiteral = 2

func newScreen(pattern string) screen {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return screen{}
	}
	parsed = parsed.Simplify()
	return screen{literals: requiredLiterals(parsed), minWidth: minWidth(parsed), nonASCII: onlyNonASCII(parsed)}
}

func requiredLiterals(re *syntax.Regexp) [][]byte {
	set, ok := literalSet(re)
	if !ok || len(set) == 0 {
		return nil
	}
	seen := map[string]bool{}
	literals := make([][]byte, 0, len(set))
	for _, literal := range set {
		if len(literal) < minScreenLiteral {
			return nil
		}
		if !seen[literal] {
			seen[literal] = true
			literals = append(literals, []byte(literal))
		}
	}
	return literals
}

var admitEveryLine screen

// admitsFile reports whether the file may contain a match. folded may be nil.
func (sc screen) admitsFile(folded *foldedText) bool {
	return folded == nil || sc.literals == nil || containsAny(folded.data, sc.literals)
}

// admitsLine reports whether line i, given as line, may contain a match.
func (sc screen) admitsLine(folded *foldedText, i int, line []byte) bool {
	if len(line) < sc.minWidth {
		return false
	}
	if sc.nonASCII && !hasNonASCII(line) {
		return false
	}
	return folded == nil || sc.literals == nil || containsAny(folded.lines[i], sc.literals)
}

// foldedText is an ASCII-lowercased copy of a file whose lines align byte for byte
// with the original.
type foldedText struct {
	data  []byte
	lines [][]byte
}

// Case-insensitive Go regexps fold U+017F to "s" and U+212A to "k". ASCII folding
// cannot represent that, so such files get no folded view and every rule runs.
var (
	longS      = []byte("\u017F")
	kelvinSign = []byte("\u212A")
)

func foldText(data []byte) *foldedText {
	if bytes.Contains(data, longS) || bytes.Contains(data, kelvinSign) {
		return nil
	}
	folded := make([]byte, len(data))
	for i, b := range data {
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		folded[i] = b
	}
	return &foldedText{data: folded, lines: splitLines(folded)}
}

func containsAny(haystack []byte, needles [][]byte) bool {
	for _, needle := range needles {
		if bytes.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

func hasNonASCII(line []byte) bool {
	for _, b := range line {
		if b >= 0x80 {
			return true
		}
	}
	return false
}

func literalSet(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		literal := string(re.Rune)
		for i := 0; i < len(literal); i++ {
			if literal[i] >= 0x80 {
				return nil, false
			}
		}
		return []string{strings.ToLower(literal)}, true
	case syntax.OpCapture, syntax.OpPlus:
		return literalSet(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return literalSet(re.Sub[0])
		}
		return nil, false
	case syntax.OpConcat:
		var best []string
		found := false
		consider := func(set []string) {
			if !found || shortest(set) > shortest(best) || shortest(set) == shortest(best) && len(set) < len(best) {
				best, found = set, true
			}
		}
		var run []string
		for _, sub := range re.Sub {
			if exact, ok := exactSet(sub); ok {
				if run == nil {
					run = exact
				} else if product, ok := crossProduct(run, exact); ok {
					run = product
				} else {
					consider(run)
					run = exact
				}
				continue
			}
			if run != nil {
				consider(run)
				run = nil
			}
			if set, ok := literalSet(sub); ok {
				consider(set)
			}
		}
		if run != nil {
			consider(run)
		}
		return best, found
	case syntax.OpAlternate:
		var union []string
		for _, sub := range re.Sub {
			set, ok := literalSet(sub)
			if !ok {
				return nil, false
			}
			union = append(union, set...)
		}
		return union, true
	default:
		return nil, false
	}
}

func minWidth(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		// One byte per rune is a lower bound even when case folding matches a
		// shorter encoding than the literal's own.
		return len(re.Rune)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		return minWidth(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min * minWidth(re.Sub[0])
	case syntax.OpConcat:
		total := 0
		for _, sub := range re.Sub {
			total += minWidth(sub)
		}
		return total
	case syntax.OpAlternate:
		least := -1
		for _, sub := range re.Sub {
			if w := minWidth(sub); least < 0 || w < least {
				least = w
			}
		}
		if least < 0 {
			return 0
		}
		return least
	default:
		return 0
	}
}

func onlyNonASCII(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r < 0x80 {
				return false
			}
		}
		return len(re.Rune) > 0
	case syntax.OpCharClass:
		for i := 0; i < len(re.Rune); i += 2 {
			if re.Rune[i] < 0x80 {
				return false
			}
		}
		return len(re.Rune) > 0
	case syntax.OpCapture, syntax.OpPlus:
		return onlyNonASCII(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min >= 1 && onlyNonASCII(re.Sub[0])
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if onlyNonASCII(sub) {
				return true
			}
		}
		return false
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !onlyNonASCII(sub) {
				return false
			}
		}
		return len(re.Sub) > 0
	default:
		return false
	}
}

// maxExactSet bounds how many concrete strings a small character class or a product
// of adjacent exact parts may expand into.
const maxExactSet = 64

// exactSet returns every lowercase ASCII string re can match when that set is small.
func exactSet(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return literalSet(re)
	case syntax.OpCharClass:
		seen := map[string]bool{}
		var set []string
		for i := 0; i < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if hi >= 0x80 || int(hi-lo) >= maxExactSet {
				return nil, false
			}
			for r := lo; r <= hi; r++ {
				value := strings.ToLower(string(r))
				if !seen[value] {
					seen[value] = true
					set = append(set, value)
				}
			}
			if len(set) > maxExactSet {
				return nil, false
			}
		}
		return set, len(set) > 0
	case syntax.OpCapture:
		return exactSet(re.Sub[0])
	case syntax.OpConcat:
		run := []string{""}
		for _, sub := range re.Sub {
			exact, ok := exactSet(sub)
			if !ok {
				return nil, false
			}
			if run, ok = crossProduct(run, exact); !ok {
				return nil, false
			}
		}
		return run, true
	case syntax.OpAlternate:
		var union []string
		for _, sub := range re.Sub {
			exact, ok := exactSet(sub)
			if !ok {
				return nil, false
			}
			union = append(union, exact...)
		}
		return union, len(union) <= maxExactSet
	default:
		return nil, false
	}
}

func crossProduct(left, right []string) ([]string, bool) {
	if len(left)*len(right) > maxExactSet {
		return nil, false
	}
	out := make([]string, 0, len(left)*len(right))
	for _, l := range left {
		for _, r := range right {
			out = append(out, l+r)
		}
	}
	return out, true
}

func shortest(set []string) int {
	n := -1
	for _, s := range set {
		if n < 0 || len(s) < n {
			n = len(s)
		}
	}
	return n
}
