# Contributing to repyy

Thank you for helping developers inspect unfamiliar repositories more safely.
Contributions that reduce false positives are as valuable as new detections.

## Before you start

- Use a supported Go version from `go.mod`.
- Read the README and `docs/COVERAGE.md`.
- Keep the detailed Markdown guide for a topic aligned with its matching web
  guide when user-visible behavior changes. `README.md` is the entry point;
  put command and configuration detail in `docs/`.
- Search existing issues before proposing a large change.
- Open an issue before changing output compatibility, verdict behavior, remote
  access, or ruleset distribution.

Never submit live malware, working credentials, private source, personal data,
or exploit-ready archives. Use the smallest inert synthetic fixture that proves
the behavior.

## Development workflow

```sh
git clone https://github.com/Kevin-Umali/repyy.git
cd repyy
make check
make security
make build
```

Keep changes focused and use `gofmt`. The CLI entry point stays tiny; put logic
in the package that owns the responsibility. Avoid generic `utils` packages,
unnecessary interfaces, hidden global state, and exported APIs used by only one
internal package.

### Test layout

- Unit tests are colocated as `*_test.go` beside the package under test.
- Reusable inert files belong under that package's `testdata/` directory.
- Cross-package or built-binary checks belong in `test/integration/`.
- Every detection needs a positive test and a realistic benign negative test.
- Regression tests should name the bug or false-positive class they prevent.

Do not move all tests into one isolated folder: that fights Go's package test
model and makes ownership less clear.

## Adding or changing a detection

A rule or structured detector must include:

1. A stable, documented ID and category.
2. Separate severity and confidence justified by behavior, not a campaign name.
3. Relevant file/path scope and context handling.
4. A clear message and actionable remediation.
5. A reliable public source for campaign IOCs or malicious-package names,
   including the review date and affected versions when known.
6. Inert positive tests, benign negative tests, and a false-positive analysis.

Prefer structured parsing and correlated behaviors over broad token regexes.
Documentation, tests, security tools, and signature definitions legitimately
contain dangerous-looking strings. Do not silence those matches globally;
classify and downgrade their context. Never use comment language or contributor
nationality as a malicious signal.

### Intelligence changes

Every package or file-hash indicator needs a stable advisory identifier,
affected versions when published, a description, dates, and an HTTPS primary
source. Run `make intel` only when intentionally refreshing the curated GitHub
advisory metadata; it performs network requests through the authenticated `gh`
CLI. The command rewrites generated metadata, so review the diff and run the
full checks afterward.

Never add an intelligence signing private key to a commit, fixture, issue, or
pull request. Releases sign the exported snapshot in GitHub Actions; the public
verification key is intentionally committed under `keys/`.

## Pull requests

`CONTRIBUTING.md` is guidance; it does not fill in a pull request automatically.
GitHub uses `.github/pull_request_template.md` for the automatic PR body.

In the pull request:

- explain behavior and tradeoffs rather than only listing files;
- include exact verification commands and results;
- call out changes to privacy, network access, execution, coverage, schema,
  severity/confidence, or compatibility;
- update documentation and examples with user-visible behavior;
- keep generated scan reports and binaries out of the commit; and
- resolve review comments rather than hiding them in follow-up commits.

Maintainers may ask for a narrower rule or more negative tests when a detection
would create noisy accusations. Security-sensitive reports belong in GitHub's
private vulnerability reporting flow described in `SECURITY.md`.
