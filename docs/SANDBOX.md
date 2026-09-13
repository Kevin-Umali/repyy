# Docker sandbox scanning

Docker mode is opt-in. Before the first scan, start Docker Desktop (macOS or
Windows) or Docker Engine (Linux) and verify that the daemon responds with
`docker version`.

Each GitHub release includes `repyy-sandbox-image.txt` with its exact image
reference and digest. Pull that reference before scanning:

```sh
docker pull ghcr.io/kevin-umali/repyy-sandbox@sha256:<published-digest>
docker image inspect ghcr.io/kevin-umali/repyy-sandbox@sha256:<published-digest>
```

Use the image reference for your installed release; do not substitute a
mutable `latest` tag. The release workflow signs and verifies the image with
Sigstore Cosign. To verify it yourself, use the version in your release tag
and the published digest:

```sh
cosign verify 'ghcr.io/kevin-umali/repyy-sandbox@sha256:<published-digest>' \
  --certificate-identity 'https://github.com/Kevin-Umali/repyy/.github/workflows/release.yml@refs/tags/v<version>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

repyy checks that the pinned image is present locally; verify the binary's
signed checksum and the image signature separately when installing.
Then scan a local folder and save a report:

```sh
repyy scan ./untrusted-repository --sandbox=docker \
  --format html --output repyy-docker-report.html
```

Missing Docker or the pinned image is a preflight error; repyy never silently
falls back to a host scan.

Multiple targets preserve input order. One failed target remains visible as
`SCAN INCOMPLETE` while successful targets retain their findings. Timeouts,
denied mounts, malformed or oversized result JSON, and container exits are
reported as incomplete or preflight errors as appropriate. Container paths and
tokens are never copied into the final report.

Docker mode accepts local paths and HTTPS remotes. It rejects SSH URLs and
`--keep-workdir` because the temporary checkout and credential boundary must
remain intact. `--sandbox=vm` and `--sandbox=auto` are reserved for a later
release. See [VM-GUIDES.md](VM-GUIDES.md) for manual alternatives.

For a local path, repyy mounts the input read-only into a temporary analysis
container, disables networking, and writes bounded JSON back to the host. For
an HTTPS remote, a disposable networked fetch stage performs a shallow clone;
the separate analysis stage has no Git credentials and no network. The host
validates the bounded result, then writes HTML atomically with normal user
permissions. HTML opens directly as a local `file://` page; clicking a source
link can open a provider website and use the browser network. Keep output in a
narrow directory and treat it as sensitive local review data.

## Git's untrusted `.git` boundary

Git warns against running commands inside a `.git` directory received from an
untrusted archive or copy. A local repyy scan treats that directory only as
data; it does not run Git in it. An HTTPS scan makes a fresh clone instead of
using a supplied `.git` directory. The fetch stage disables hooks, templates,
submodule recursion, other protocols, and redirects, and ignores inherited Git
configuration. It runs under a narrow container user. The analysis stage has
no Git credentials or network.

If you need to operate on a supplied local `.git` directory, follow Git's
[security guidance](https://git-scm.com/docs/git#_security): make a clean
`git clone --no-local` inside a disposable VM, preferably serving the source
with an unprivileged user. Git's
[upload-pack guidance](https://git-scm.com/docs/git-upload-pack#_security)
explains why that extra user boundary matters. Host-mode remote scans run Git
as your account; choose Docker mode for an HTTPS remote when you want the
stronger process boundary.
