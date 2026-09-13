# repyy

[![CI](https://github.com/Kevin-Umali/repyy/actions/workflows/ci.yml/badge.svg)](https://github.com/Kevin-Umali/repyy/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Kevin-Umali/repyy/actions/workflows/codeql.yml/badge.svg)](https://github.com/Kevin-Umali/repyy/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Scan an unfamiliar repository before installing its dependencies or running its
code. `repyy` is a local, read-only malware and supply-chain scanner for source
you do not fully trust. It reads files as data and does not import, build, test,
or execute the target.

## Quick start

Install a release from [GitHub Releases](https://github.com/Kevin-Umali/repyy/releases),
or use one of the package-manager commands below:

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

Open `repyy-report.html` locally. The report is self-contained and makes no
network requests while it is displayed; a source link can open the provider
website when clicked. Treat reports as sensitive review data.

`NO FINDINGS` means no enabled rule matched in completed coverage. It does not
prove that a repository is safe. Treat `SCAN INCOMPLETE` as unresolved and
review its warnings before relying on the result.

## Documentation

Open the checked-in [documentation site](site/docs.html) locally for the guided
web experience ([preview instructions](site/README.md)):

- [Install and run a first scan](site/installation.html)
- [CLI commands and flags](site/cli.html)
- [Trusted configuration](site/configuration.html)
- [Docker and manual VM isolation](site/isolation.html)
- [Detection coverage and limits](site/coverage.html)
- [Offline intelligence and updates](site/intelligence.html)
- [AI agent skill workflow](site/agent-skill.html)

The same topics are available as detailed Markdown guides for repository
readers: [installation](docs/INSTALLATION.md), [CLI](docs/CLI.md),
[configuration](docs/CONFIGURATION.md), [Docker sandbox](docs/SANDBOX.md),
[manual VM workflows](docs/VM-GUIDES.md), and [coverage](docs/COVERAGE.md).

The optional [AI agent skill](skills/repyy/SKILL.md) teaches compatible agents
to scan before execution and to report incomplete coverage. Install it with:

```sh
npx skills add Kevin-Umali/repyy --skill repyy
```

This optional installer needs Node/npm, Git, and network access. The skill
contains instructions; install the `repyy` CLI separately. See the
[web skill guide](site/agent-skill.html) for the full workflow.

## Contributing

```sh
git clone https://github.com/Kevin-Umali/repyy.git
cd repyy
make check
make security
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing detections, output,
network behavior, or report compatibility. See [SECURITY.md](SECURITY.md) for
private vulnerability reports.

## License

MIT. Third-party intelligence sources are listed in [NOTICE](NOTICE).
