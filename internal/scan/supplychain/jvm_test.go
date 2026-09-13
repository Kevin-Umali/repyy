package supplychain

import "testing"

func TestJVMWrapperDoesNotTrustOfficialHostOnUnexpectedPort(t *testing.T) {
	if trustedJVMWrapperDistribution("gradle", "https://services.gradle.org:444/distributions/gradle-9.1-bin.zip") {
		t.Fatal("unexpected port was treated as the official distribution endpoint")
	}
}
