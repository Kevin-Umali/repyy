# Repyy benchmark 1.2.0

Repyy: 0.6.0-dev
Expected risky fixtures detected: 11/11
Clean controls incorrectly flagged at high/critical: 0/11
Unsupported/skipped fixture scans: 0
Incomplete fixture scans: 0

This measures this inert corpus only, not general accuracy or proof of safety. Every observed rule is recorded in results.json.

| Case | Expected rules | Missing | Control high/critical |
| --- | --- | --- | --- |
| lifecycle | PKG-001 | none | none |
| startup | IMPORT-001 | none | none |
| disguised-asset | EXEC-001 | none | none |
| folder-open | IDE-001 | none | none |
| git-hook | GITHOOK-001 | none | none |
| obfuscated-download | CHAIN-001 | none | none |
| credential-path | CRED-001 | none | none |
| docker-socket | DOCKER-001 | none | none |
| sourced-package | IOC-PKG-GHSA-rqwx-v86m-wwff | none | none |
| axios-response-execution | FLOW-001 | none | none |
| literal-recovery | DECODE-001 | none | none |
