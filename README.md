# repyy

[![CI](https://github.com/Kevin-Umali/repyy/actions/workflows/ci.yml/badge.svg)](https://github.com/Kevin-Umali/repyy/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Kevin-Umali/repyy/actions/workflows/codeql.yml/badge.svg)](https://github.com/Kevin-Umali/repyy/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Inspect a take-home assignment before installing dependencies, starting the project, or opening its
folder in your IDE. `repyy` provides a local static security review of unfamiliar source
repositories. It reads files as data and does not import, build, test, or execute the target.

**Repyy identifies risks. It cannot prove that a repository is safe.**

[View the website](https://repyy.dev/) · [View a sample report](https://repyy.dev/demo/sample/sample.html) · [Trust and Limitations](docs/TRUST.md) ·
[Verify releases](docs/VERIFICATION.md) · [Security testing](docs/SECURITY-TESTING.md) ·
[About the maintainer](docs/ABOUT.md)

## Quick start

Install a release from [GitHub Releases](https://github.com/Kevin-Umali/repyy/releases), or use one
of the package-manager commands below:

```sh
# macOS
brew install --cask Kevin-Umali/tap/repyy

# Windows PowerShell
scoop bucket add repyy https://github.com/Kevin-Umali/scoop-bucket
scoop install repyy/repyy

# Any platform with Go
go install github.com/Kevin-Umali/repyy/cmd/repyy@latest
```

Scan a local checkout and save a reviewable report:

```sh
repyy version
repyy scan ./unfamiliar-repository --format html --output repyy-report.html
```

Open `repyy-report.html` locally. The report is self-contained and makes no network requests while
it is displayed; a source link can open the provider website when clicked. Treat reports as
sensitive review data.

`NO FINDINGS` means no enabled rule matched in completed coverage. It does not prove that a
repository is safe. Treat `SCAN INCOMPLETE` as unresolved and review its warnings before relying on
the result.

## Documentation

Use [repyy.dev/docs](https://repyy.dev/docs/) for the rendered documentation. Inside GitHub, use the Markdown guides:

- [Install and run a first scan](docs/INSTALLATION.md)
- [CLI commands and flags](docs/CLI.md)
- [Trusted configuration](docs/CONFIGURATION.md)
- [Docker and manual VM isolation](docs/SANDBOX.md)
- [Detection coverage and limits](docs/COVERAGE.md)
- [Trust and limitations](docs/TRUST.md)
- [Release verification](docs/VERIFICATION.md)
- [Security testing](docs/SECURITY-TESTING.md)

Development and deployment instructions for the Astro site are in [site/README.md](site/README.md).

The optional [AI agent skill](skills/repyy/SKILL.md) teaches compatible agents to scan before
execution and to report incomplete coverage. Install it with:

```sh
npx skills add Kevin-Umali/repyy --skill repyy
```

This optional installer needs Node/npm, Git, and network access. The skill contains instructions;
install the `repyy` CLI separately. See the [web skill guide](https://repyy.dev/agent-skill/) for the
full workflow.

## Contributing

```sh
git clone https://github.com/Kevin-Umali/repyy.git
cd repyy
make check
make security
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing detections, output, network behavior, or
report compatibility. See [SECURITY.md](SECURITY.md) for private vulnerability reports.

## License

MIT. Third-party intelligence sources are listed in [NOTICE](NOTICE).
