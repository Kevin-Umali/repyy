// Package workflow detects risky GitHub Actions workflow structures.
package workflow

import (
	"regexp"
	"strings"

	"github.com/Kevin-Umali/repyy/internal/model"
	"gopkg.in/yaml.v3"
)

type FindingFactory func(id, category string, severity model.Severity, confidence model.Confidence, path string, line int, message, evidence, remediation string) model.Finding

type riskFinding struct {
	id, category, message, evidence, remediation string
	line                                         int
	severity                                     model.Severity
	confidence                                   model.Confidence
	disposition                                  model.Disposition
}

type reporter struct {
	path       string
	newFinding FindingFactory
	add        func(model.Finding)
}

func (r reporter) report(spec riskFinding) {
	finding := r.newFinding(spec.id, spec.category, spec.severity, spec.confidence, r.path, spec.line, spec.message, spec.evidence, spec.remediation)
	finding.Context = "ci-workflow"
	finding.Disposition = spec.disposition
	r.add(finding)
}

var artifactExecutionCommand = regexp.MustCompile(`(?i)^(?:\./\S+|(?:bash|sh|node|python[0-9.]*)\s+(?:\./)?\S+|npm\s+(?:install|ci)\b|chmod\s+\+x\b)`)
var untrustedEventExpression = regexp.MustCompile(`(?i)\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|discussion)[^}]*\}\}`)
var secretExpression = regexp.MustCompile(`(?i)\$\{\{\s*secrets\.[^}]+\}\}`)
var outboundCommand = regexp.MustCompile(`(?i)\b(?:curl|wget|Invoke-WebRequest)\b`)

// ScanRisks inspects a decoded workflow document. The caller supplies finding
// construction so this package stays independent from scanner internals.
func ScanRisks(path string, root *yaml.Node, newFinding FindingFactory, add func(model.Finding)) {
	r := reporter{path: path, newFinding: newFinding, add: add}
	jobs := field(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return
	}
	scanBlockRuns(jobs, r)
	triggers := field(root, "on")
	if hasTrigger(triggers, "pull_request_target") || hasTrigger(triggers, "issue_comment") || hasTrigger(triggers, "workflow_run") {
		scanCacheWriteOverride(root, jobs, r)
	}
	if hasTrigger(triggers, "workflow_run") {
		scanWorkflowRunArtifacts(jobs, r)
	}
	if hasTrigger(triggers, "pull_request") {
		scanPullRequestRunner(jobs, r)
	}
}

func field(mapping *yaml.Node, name string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == name {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func hasTrigger(triggers *yaml.Node, name string) bool {
	if triggers == nil {
		return false
	}
	switch triggers.Kind {
	case yaml.ScalarNode:
		return triggers.Value == name
	case yaml.SequenceNode:
		for _, trigger := range triggers.Content {
			if trigger.Value == name {
				return true
			}
		}
	case yaml.MappingNode:
		return field(triggers, name) != nil
	}
	return false
}

func writeCapableCacheMode(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(node.Value))
	return mode == "write" || mode == "write-only"
}

func scanCacheWriteOverride(root, jobs *yaml.Node, r reporter) {
	workflowMode, seenLines := field(root, "cache-mode"), map[int]bool{}
	for i := 1; i < len(jobs.Content); i += 2 {
		mode := field(jobs.Content[i], "cache-mode")
		if mode == nil {
			mode = workflowMode
		}
		if !writeCapableCacheMode(mode) || seenLines[mode.Line] {
			continue
		}
		seenLines[mode.Line] = true
		r.report(riskFinding{
			id: "CICD-007", category: "ci-cache-integrity", line: mode.Line,
			severity: model.SeverityHigh, confidence: model.ConfidenceMedium, disposition: model.DispositionReview,
			message: "Low-trust workflow explicitly allows cache writes", evidence: "cache-mode: " + mode.Value,
			remediation: "Keep low-trust jobs read-only for cache access, or verify that they cannot process untrusted input before saving a cache.",
		})
	}
}

func scanWorkflowRunArtifacts(jobs *yaml.Node, r reporter) {
	for i := 1; i < len(jobs.Content); i += 2 {
		steps := field(jobs.Content[i], "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		downloaded := false
		for _, step := range steps.Content {
			uses := field(step, "uses")
			if uses != nil && strings.HasPrefix(strings.ToLower(strings.TrimSpace(uses.Value)), "actions/download-artifact@") {
				if runID := field(field(step, "with"), "run-id"); runID != nil && strings.Contains(runID.Value, "github.event.workflow_run.id") {
					downloaded = true
				}
			}
			run := field(step, "run")
			if !downloaded || run == nil || !executesAfterArtifactDownload(run.Value) {
				continue
			}
			r.report(riskFinding{
				id: "CICD-006", category: "ci-artifact-trust", line: run.Line,
				severity: model.SeverityHigh, confidence: model.ConfidenceMedium, disposition: model.DispositionReview,
				message: "Privileged workflow_run job executes after downloading an artifact", evidence: "artifact download followed by a command",
				remediation: "Treat upstream artifacts as untrusted data; validate them and avoid executing downloaded content in this privileged job.",
			})
		}
	}
}

func executesAfterArtifactDownload(script string) bool {
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") && artifactExecutionCommand.MatchString(line) {
			return true
		}
	}
	return false
}

func scanPullRequestRunner(jobs *yaml.Node, r reporter) {
	for i := 1; i < len(jobs.Content); i += 2 {
		runner := field(jobs.Content[i], "runs-on")
		if !containsSelfHostedRunner(runner) {
			continue
		}
		r.report(riskFinding{
			id: "CICD-008", category: "ci-runner-trust", line: runner.Line,
			severity: model.SeverityHigh, confidence: model.ConfidenceMedium, disposition: model.DispositionReview,
			message: "Pull-request workflow runs on a self-hosted runner", evidence: "pull_request with self-hosted runner",
			remediation: "Verify repository visibility, fork approval, runner isolation, and what untrusted pull-request code can access.",
		})
	}
}

func containsSelfHostedRunner(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.ScalarNode {
		return strings.EqualFold(strings.TrimSpace(node.Value), "self-hosted")
	}
	for _, child := range node.Content {
		if containsSelfHostedRunner(child) {
			return true
		}
	}
	return false
}

func scanBlockRuns(jobs *yaml.Node, r reporter) {
	for i := 1; i < len(jobs.Content); i += 2 {
		steps := field(jobs.Content[i], "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		for _, step := range steps.Content {
			run := field(step, "run")
			if run == nil || run.Style&(yaml.LiteralStyle|yaml.FoldedStyle) == 0 {
				continue
			}
			var commands strings.Builder
			for _, line := range strings.Split(run.Value, "\n") {
				if !strings.HasPrefix(strings.TrimSpace(line), "#") {
					commands.WriteString(line)
					commands.WriteByte('\n')
				}
			}
			script := commands.String()
			if untrustedEventExpression.MatchString(script) {
				r.report(riskFinding{
					id: "CICD-002", category: "ci-secret-exposure", line: run.Line,
					severity: model.SeverityHigh, confidence: model.ConfidenceMedium,
					message: "CI workflow interpolates untrusted event data into a shell command", evidence: "untrusted event expression in run block",
					remediation: "Pass untrusted event data through an environment variable and quote it for the shell, or avoid shell interpolation.",
				})
			}
			if secretExpression.MatchString(script) && outboundCommand.MatchString(script) {
				r.report(riskFinding{
					id: "CICD-004", category: "ci-secret-exposure", line: run.Line,
					severity: model.SeverityCritical, confidence: model.ConfidenceHigh,
					message: "CI command sends a secret to an external endpoint", evidence: "secret expression and outbound command in run block",
					remediation: "Review the destination and remove unneeded secret transfer from this workflow.",
				})
			}
		}
	}
}
