package model

import "testing"

func TestIncompleteDecisionOverridesFindings(t *testing.T) {
	for _, verdict := range []string{VerdictNoFindings, VerdictReview, VerdictDoNotRun} {
		result := RepoResult{Verdict: verdict, Coverage: Coverage{Complete: false}}
		if result.DecisionStatus() != "SCAN INCOMPLETE" {
			t.Fatalf("incomplete %s hidden", verdict)
		}
	}
	if (RepoResult{Verdict: VerdictNoFindings, Coverage: Coverage{Complete: true}}).DecisionStatus() != "NO RELEVANT FINDINGS DETECTED" {
		t.Fatal("unexpected completed wording")
	}
}
