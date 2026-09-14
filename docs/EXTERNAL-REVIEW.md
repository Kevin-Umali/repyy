# Independent review brief

Reviewed: 2026-09-15. Describes the trust-roadmap changes; unreleased features are identified
explicitly.

Status: prepared for review; no independent review is claimed. Contacting reviewers and publishing
their work require an actual engagement. Local implementation work cannot satisfy that launch gate.

## Entry conditions

Before inviting review, supply a fixed release tag and full commit, public trust claims, successful
release-download verification, inert demo/benchmark results, fuzz-run evidence and known issue
status. Do not use a moving branch name as the reviewed version.

## Scope

Review threat-model accuracy; target-code non-execution; host Git/SSH retrieval and credential
handling; temporary-directory and container cleanup; archive and symlink confinement; Windows/Unix
file handling; Docker fetch versus scan boundary; terminal and HTML escaping; source links and
secret redaction; signed intelligence update/rollback; release identity, signing, SBOM scope,
attestations and publication ordering.

Use inert inputs. Do not submit private assignments, active malware or real credentials. Runtime
execution of target projects, general detection completeness and hosted private scanning are out of
scope.

## Reviewer selection

Prefer reviewers with public work on Go parser security, filesystem confinement, Git/SSH security,
container boundaries or software supply-chain verification. Ask for examples of relevant reviews,
conflicts of interest, availability, proposed method and permission to publish their report. Do not
claim that popularity, a badge, or a generic penetration-testing credential substitutes for relevant
experience.

Possible channels to investigate include maintainers/researchers with relevant public advisories,
established open-source security review programs and qualified consultants. No individual is
represented here as available or committed. A useful initial engagement is a narrowly scoped
claim-and-boundary review; expand only after its findings are addressed.

## Deliverable template

- Reviewer identity and relevant public background:
- Relationship to maintainer and conflicts:
- Reviewed Repyy release and full commit:
- Review dates and methods:
- Exact in-scope and excluded components:
- Finding ID, severity, affected behavior and inert reproduction:
- Maintainer response and fix commit:
- Retested version/commit and result:
- Remaining limitations:
- Public report URL and publication permission:

## Findings register

| ID                            | Severity | Scope / evidence        | Maintainer response | Fix commit | Retest | Status            |
| ----------------------------- | -------- | ----------------------- | ------------------- | ---------- | ------ | ----------------- |
| No external findings recorded | —        | Review has not occurred | —                   | —          | —      | Awaiting reviewer |

Publish the complete scope and report alongside remediation status. Never display an audited or
independently-reviewed badge before that evidence exists. Keep unresolved findings visible and do
not silently narrow the claimed review scope.

## Finding a reviewer

[OSTIF's audit request channel](https://ostif.org/get-an-audit/) is one concrete starting point for
an independent open-source audit. Evaluate reviewers against the scope above, ask for relevant Go
parser and supply-chain review experience, and agree on disclosure, remediation, and retesting. No
request has been submitted, and availability, funding, and acceptance are not established.
