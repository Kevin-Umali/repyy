# Installation and first scan

repyy is a native command-line program. Install it before opening or building an unfamiliar
repository. During a normal scan, the scanner reads target files as data and does not intentionally
install target packages or run target code. Remote scans may invoke Git; Docker mode also invokes
the Docker client and Repyy worker. See [Trust and Limitations](TRUST.md) for the full boundary.

For a first review, verify the binary and save an HTML report:

```sh
repyy version
repyy scan ./unfamiliar-repository --format html --output repyy-report.html
```

## Prerequisites

- macOS, Linux, or Windows with a supported repyy release binary.
- Git on the host only for remote scans in the default host mode. The Docker image includes Git for
  its HTTPS fetch stage; local folder scans do not invoke Git.
- Docker Desktop (macOS/Windows) or Docker Engine (Linux) only for `--sandbox=docker`.
- A browser for opening an HTML report.

## Verify a downloaded release

Before extracting or installing a manual archive or package, authenticate its signed checksum list
and compare your download with that list. Follow [Releases and Verification](VERIFICATION.md) for
the exact commands, supported release evidence, and platform alternatives. A checksum from an
unauthenticated list only checks consistency; it does not establish who published the bytes.

## macOS

```sh
brew install --cask Kevin-Umali/tap/repyy
```

## Linux and manual archives

Linux releases include `.deb`, `.rpm`, and `.apk` packages. Archives for all desktop platforms are
published on [GitHub Releases](https://github.com/Kevin-Umali/repyy/releases). Verify the published
checksum, extract the archive, and put `repyy` on `PATH`. Go users can install a source build with:

```sh
go install github.com/Kevin-Umali/repyy/cmd/repyy@latest
```

## Windows

Scoop installs repyy from its bucket manifest:

```powershell
scoop bucket add repyy https://github.com/Kevin-Umali/scoop-bucket
scoop install repyy/repyy
repyy --help
```

Adding a Scoop bucket uses Git. That Git requirement belongs to Scoop setup; it is separate from the
host-mode Git requirement for scanning HTTPS remotes. For a manual install, download the Windows ZIP
archive from [GitHub Releases](https://github.com/Kevin-Umali/repyy/releases). Verify its checksum
first. The following PowerShell sequence extracts it, copies `repyy.exe` into a dedicated user
directory, and adds that directory to the user `PATH`:

```powershell
$zip = 'C:\path\to\the-downloaded-repyy-windows-archive.zip' # replace with the actual file path
$bin = "$env:LOCALAPPDATA\repyy\bin"
$extract = Join-Path $env:TEMP ("repyy-extract-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force $bin | Out-Null
Expand-Archive -LiteralPath $zip -DestinationPath $extract
$exe = Get-ChildItem -LiteralPath $extract -Filter repyy.exe -Recurse | Select-Object -First 1
if (-not $exe) { throw 'repyy.exe was not found in the ZIP' }
Copy-Item -LiteralPath $exe.FullName -Destination (Join-Path $bin 'repyy.exe')
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $bin) {
  $newPath = if ($userPath) { $userPath.TrimEnd(';') + ';' + $bin } else { $bin }
  [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
}
```

Replace the sample ZIP path with the archive you downloaded, choosing the `amd64` or `arm64` Windows
build that matches your machine. Open a new PowerShell window, then run `repyy version`.

## Verify and scan

```sh
repyy --help
repyy version
repyy intel status
repyy scan ./repository
repyy scan ./repository --format html --output report.html
```

Open `report.html` directly from the file manager or browser. Its CSS and JavaScript are embedded,
so it works as a local `file://` page. Clicking a Git provider source link can open that website and
use the network; viewing the report itself makes no network requests.

For a remote repository in host mode, Git may use HTTPS or SSH. Docker mode accepts HTTPS only and
requires a prepared, digest-pinned release image:

```sh
repyy scan https://github.com/org/repository --sandbox=docker \
  --format html --output report.html
```

Private HTTPS credentials use `GITHUB_TOKEN`, `GITLAB_TOKEN`, or `BITBUCKET_TOKEN`; they are not
written to the clone URL or report. Host mode passes them through the Git process environment.
Docker mode uses a temporary restricted-permission environment file for retrieval, deletes it
afterward, and gives the analysis container no Git credentials. Cleanup failures are reported. The
complete image verification and isolation workflow is in [SANDBOX.md](SANDBOX.md). SSH remains
available in host mode, but Docker mode rejects SSH.

Use a local path when you already have a checkout. Use a remote URL when you want repyy to fetch a
repository. Choose `--format json` for another tool or `--format sarif` for a code-scanning system.
See [CLI.md](CLI.md) for every option and [VM-GUIDES.md](VM-GUIDES.md) for manual guest workflows.

## Troubleshooting

- `command not found`: restart the shell after changing `PATH`, then run `where.exe repyy`
  (PowerShell) or `command -v repyy` (macOS/Linux).
- Scoop cannot add the bucket: install Git and retry. This affects Scoop setup, not local-folder
  scans.
- A remote scan fails: confirm Git is installed for host mode, the HTTPS or SSH URL is reachable,
  and the matching token or SSH agent is available. Docker mode accepts HTTPS only.
- An HTML file looks blank: open it in a current browser and confirm the file was fully written. A
  readable summary is included when JavaScript is off.
- A scan is incomplete: read the timeout, permission, clone, archive, or file limit reason before
  relying on the result.
