# Repyy demo and paired benchmark

The [public demo](https://repyy.dev/demo/) opens a report produced with a local
`0.6.0-dev` build from the 0.6.0 code. `cases.json` contains eleven inert risky
fixtures and eleven paired benign controls. The runner materializes them as text,
invokes only Repyy, and removes them. All eleven expected signals were found; no
control received a high or critical finding, and all scans were complete. This
is a narrow fixture result, not a general accuracy score or an attested release build.

Three cases exercise the new sourced package indicator, supported Axios
fetch-to-execution flow, and bounded literal decoding. The earlier eight cases
remain for lifecycle, startup, disguised asset, editor, hook, download-string,
credential-path, and Docker socket behavior. The
[HTML report](https://repyy.dev/demo/sample/sample.html),
[JSON report](https://repyy.dev/demo/sample/sample.json), and
[paired results](https://repyy.dev/demo/sample/results.json) show the observable evidence.

To reproduce, build Repyy itself and run the trusted runner:

```sh
go build -trimpath -ldflags '-X main.version=0.6.0-dev' -o /tmp/repyy-demo ./cmd/repyy
python3 scripts/benchmark.py --binary /tmp/repyy-demo --output /tmp/repyy-demo-output --check
```

The runner does not install dependencies or execute fixture code, package
scripts, Docker commands, IDE tasks, Git hooks, or remote payloads.

## Pinned corpus context

The demo also gives context from a static review of the
[malicious-repositories corpus at commit dc82f332](https://github.com/xndbogdan/malicious-repositories/tree/dc82f332dae0f4e9ea6bdc1d8341c7743c59913f).
Repyy 0.5.3-dev scanned the corpus as data with rules `2026.09.19` and intelligence
`2026-09-12.1`. The baseline covered 15 targets: 13 complete scans and two incomplete scans
with four skipped files. This is a pinned observation, not a measurement of Repyy 0.6.0.

That review showed three paths: an omitted `process-log` package indicator, an Axios
response passed to `eval` without fetch-to-execution correlation, and a declared
`vite-tsconsole-log` package in a scan with unreadable locale files. Current Repyy rules
have focused tests for the added intelligence and correlation behavior. A reviewed,
isolated replay of the pinned corpus is still needed before publishing current per-sample
results. No project command or remote payload was run for this documentation update.

[OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) is an advisory source,
distinct from the repository corpus. Neither source establishes a common actor or the content
of remote second stages.

## Inert regression artifacts

Release workflows retain the inert benchmark as a regression check. It is not the
real-corpus measurement and does not establish general detection accuracy.
