package supplychain_test

import (
	"strings"
	"testing"

	"github.com/Kevin-Umali/repyy/internal/model"
)

func TestScanJVMWrapperFlagsRedirectedDistributionAndMissingChecksum(t *testing.T) {
	findings := scanInertPackageFixture(t, "gradle/wrapper/gradle-wrapper.properties", "distributionUrl=https\\://mirror.invalid/gradle-9.1-bin.zip\n")
	for _, id := range []string{"JVMWRAP-001", "JVMWRAP-002"} {
		if !hasRule(findings, id) {
			t.Fatalf("missing %s: %+v", id, findings)
		}
	}
	if finding, ok := ruleFinding(findings, "JVMWRAP-001"); !ok || finding.Severity != model.SeverityHigh || finding.Disposition != model.DispositionReview {
		t.Fatalf("unexpected source finding: %+v", finding)
	}
	if finding, ok := ruleFinding(findings, "JVMWRAP-002"); !ok || finding.Severity != model.SeverityMedium || finding.Disposition != model.DispositionHarden {
		t.Fatalf("unexpected missing checksum finding: %+v", finding)
	}
}

func TestScanJVMWrapperFlagsMalformedChecksum(t *testing.T) {
	findings := scanInertPackageFixture(t, ".mvn/wrapper/maven-wrapper.properties", "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.11/apache-maven-3.9.11-bin.zip\ndistributionSha256Sum=not-a-sha\n")
	if !hasRule(findings, "JVMWRAP-003") || hasRule(findings, "JVMWRAP-002") {
		t.Fatalf("malformed checksum was classified incorrectly: %+v", findings)
	}
	finding, _ := ruleFinding(findings, "JVMWRAP-003")
	if finding.Severity != model.SeverityHigh || finding.Disposition != model.DispositionReview {
		t.Fatalf("unexpected malformed checksum finding: %+v", finding)
	}
}

func TestScanJVMWrapperAcceptsOfficialPinnedGradleAndMavenDistributions(t *testing.T) {
	checksum := strings.Repeat("a", 64)
	for path, body := range map[string]string{
		"gradle/wrapper/gradle-wrapper.properties": "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.1-bin.zip\ndistributionSha256Sum=" + checksum + "\n",
		".mvn/wrapper/maven-wrapper.properties":    "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.11/apache-maven-3.9.11-bin.zip\ndistributionSha256Sum=" + checksum + "\n",
	} {
		findings := scanInertPackageFixture(t, path, body)
		if len(findings) != 0 {
			t.Fatalf("benign wrapper %s produced findings: %+v", path, findings)
		}
	}
}
