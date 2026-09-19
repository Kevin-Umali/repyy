package scan

import (
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
)

type ruleQualityGroup struct {
	Implementation string
	Tests          string
	RuleIDs        []string
}

// ruleQualityManifest is deliberately independent from the production catalog.
// Adding a production detector without assigning an implementation and contract
// suite here fails TestRuleQualityManifestCoversCatalog.
var ruleQualityManifest = []ruleQualityGroup{
	{
		Implementation: "BuiltinRules and scanContent generic matcher, plus workflow block inspection",
		Tests:          "TestBuiltinRegexContract, scanner context corpus, and workflow block regressions",
		RuleIDs: []string{
			"EXEC-001", "EXEC-002", "EXEC-003", "EXEC-004", "EXEC-005", "EXEC-006",
			"OBFS-001", "OBFS-002", "OBFS-003", "OBFS-006", "OBFS-007", "OBFS-008", "OBFS-009",
			"PROTO-001", "NET-001", "CHAIN-001", "CHAIN-002", "CHAIN-003", "CRED-001", "CRED-002", "ENV-001",
			"EXFIL-001", "EXFIL-002", "NET-002", "REVSHELL-001", "REVSHELL-002", "BACKDOOR-001", "BACKDOOR-002",
			"MINER-001", "EVADE-001", "FINGERPRINT-001", "IPURL-001", "IMPORT-001", "IMPORT-002", "IMPORT-003",
			"UNICODE-001", "IDE-001", "IDE-002", "IDE-003", "IDE-004", "IDE-005", "IDE-006", "AGENT-001", "AGENT-002", "CICD-001", "CICD-002", "CICD-004", "CICD-005",
			"DOCKER-001", "DOCKER-002", "DOCKER-003", "GITHOOK-001", "GITHOOK-003", "GITMETA-001", "NPMRC-001", "NPMRC-002", "LOCK-001",
			"TYPOSQUAT-001", "SOCIAL-001", "SOCIAL-002", "APT-001", "SECRET-001", "SECRET-002", "SECRET-003", "SHELL-001", "PERSIST-001", "PERSIST-002", "AUTORUN-001", "AUTORUN-002", "INSTALL-001", "FONT-001", "BUILD-001", "BUILD-002", "BUILD-003", "BUILD-004",
			"UNSERIALIZE-001", "PATH-001", "PY-001", "PY-002", "RUBY-001", "GO-001", "GO-002", "JVM-001", "JVM-002", "PHP-001", "RUST-001",
		},
	},
	{
		Implementation: "structured workflow YAML inspection",
		Tests:          "TestStructuredWorkflowRetainsEveryMutableActionLocation",
		RuleIDs:        []string{"CICD-003"},
	},
	{
		Implementation: "archive, filesystem, repository, manifest, correlation, and intelligence inspectors",
		Tests:          "TestStructuredRuleFamilyContract and targeted scanner regression tests",
		RuleIDs: []string{
			"ARCHIVE-001", "BINARY-001", "CHAIN-004", "COMBO-001", "COMBO-002", "COMBO-003", "CICD-006", "CICD-007", "CICD-008", "DOC-001", "DOC-002", "DOC-003", "DOC-004", "EXECBIT-001", "FONT-002", "FONT-003", "FONT-004", "FONT-005", "GITHOOK-002", "IDE-007", "IDE-008", "IDE-009", "IMAGE-001",
			"DOTNET-001", "IOC-HASH-SHA256", "IOC-PKG-*", "JVMWRAP-001", "JVMWRAP-002", "JVMWRAP-003", "NUGET-001", "OBFS-004", "OBFS-005", "PKG-001", "PKG-002", "PKG-003", "PKG-004",
			"PKG-005", "PKG-006", "PKG-007", "PKG-008", "PKG-009", "PHP-002", "PHP-003", "PY-003", "RUBY-002", "RUST-002", "RUST-003", "RUST-004", "RUST-005", "REPO-001", "REPO-002", "SYMLINK-001", "SYMLINK-002", "YARN-001", "YARN-002",
		},
	},
}

func TestRuleQualityManifestCoversCatalog(t *testing.T) {
	covered := map[string]ruleQualityGroup{}
	for _, group := range ruleQualityManifest {
		if group.Implementation == "" || group.Tests == "" {
			t.Fatalf("incomplete rule-quality group: %+v", group)
		}
		for _, id := range group.RuleIDs {
			if previous, exists := covered[id]; exists {
				t.Fatalf("rule %s is assigned twice (%s and %s)", id, previous.Implementation, group.Implementation)
			}
			covered[id] = group
		}
	}
	for _, info := range BuiltinRuleCatalog() {
		if _, exists := covered[info.ID]; !exists {
			t.Errorf("production rule %s lacks a rule-quality manifest entry", info.ID)
		}
	}
	for id := range covered {
		if _, exists := LookupRuleInfo(id); !exists {
			t.Errorf("rule-quality manifest contains unknown production rule %s", id)
		}
	}
}

func TestBuiltinRegexContract(t *testing.T) {
	positiveOverrides := map[string]string{
		"OBFS-009": "module.exports=a;global.",
	}
	for _, rule := range BuiltinRules() {
		rule := rule
		t.Run(rule.ID, func(t *testing.T) {
			parsed, err := syntax.Parse(rule.Pattern, syntax.Perl)
			if err != nil {
				t.Fatal(err)
			}
			positive := positiveOverrides[rule.ID]
			if positive == "" {
				positive = shortestRegexExample(parsed)
			}
			if !rule.re.MatchString(positive) {
				t.Fatalf("generated inert positive %q does not match %s", positive, rule.Pattern)
			}
			if rule.re.MatchString("ordinary project configuration") {
				t.Fatal("generic benign negative unexpectedly matched")
			}
			if rule.Remediation == "" || rule.Rationale == "" || rule.LegitimateUse == "" {
				t.Fatal("review guidance is incomplete")
			}
			if rule.MatchScope != "raw" && rule.MatchScope != "code" && rule.MatchScope != "structured" {
				t.Fatalf("invalid match scope %q", rule.MatchScope)
			}
			if rule.Disposition != model.DispositionBlock && rule.Disposition != model.DispositionReview && rule.Disposition != model.DispositionHarden && rule.Disposition != model.DispositionInformational {
				t.Fatalf("invalid disposition %q", rule.Disposition)
			}
		})
	}
}

func shortestRegexExample(expression *syntax.Regexp) string {
	switch expression.Op {
	case syntax.OpNoMatch:
		return ""
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return ""
	case syntax.OpLiteral:
		return string(expression.Rune)
	case syntax.OpCharClass:
		for _, candidate := range []rune{'a', 'A', '0', '_', ' ', ':', '/', '.', '-', '\'', '"', '\n'} {
			for index := 0; index+1 < len(expression.Rune); index += 2 {
				if candidate >= expression.Rune[index] && candidate <= expression.Rune[index+1] {
					return string(candidate)
				}
			}
		}
		if len(expression.Rune) > 0 {
			return string(expression.Rune[0])
		}
		return "x"
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return "x"
	case syntax.OpCapture:
		return shortestRegexExample(expression.Sub[0])
	case syntax.OpConcat:
		var result strings.Builder
		for _, child := range expression.Sub {
			result.WriteString(shortestRegexExample(child))
		}
		return result.String()
	case syntax.OpAlternate:
		return shortestRegexExample(expression.Sub[0])
	case syntax.OpStar, syntax.OpQuest:
		return ""
	case syntax.OpPlus:
		return shortestRegexExample(expression.Sub[0])
	case syntax.OpRepeat:
		return strings.Repeat(shortestRegexExample(expression.Sub[0]), expression.Min)
	default:
		return ""
	}
}
