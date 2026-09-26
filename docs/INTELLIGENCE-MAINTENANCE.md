# Intelligence maintenance

Normal scans never fetch advisories. `repyy intel update` downloads only the
maintainer-signed snapshot selected by the user. Feed ingestion is a separate,
explicit maintainer operation and its output is an unsigned review candidate.

## Bounded ingestion

`scripts/ingest_intelligence.py` accepts reviewed GitHub malware-advisory JSON
pages and OSV JSON files from a pinned OpenSSF malicious-packages source tree.
Alternatively, `--github-api` accepts only the HTTPS GitHub advisories API and
requires `type=malware`; local GitHub pages must also contain malware advisories.
Pagination stays on that endpoint, and redirects are rejected. Acquisition
stops at 1,000 pages, 100,000 reports, or 64 MiB. The
[GitHub API](https://docs.github.com/en/rest/security-advisories/global-advisories)
caps `per_page` at 100; the page cap therefore allows more than 10,000 records while
the byte and record caps remain in force.
The candidate stops at 16 MiB, matching the updater's download limit. The tool
prints the exact input counts, package count, serialized byte count, and limit.

```sh
go run ./cmd/repyy intel export > /tmp/base-snapshot.json
python3 scripts/ingest_intelligence.py \
  --github-page /reviewed/github-malware-page-1.json \
  --openssf-dir /reviewed/ossf-malicious-packages-at-PIN/osv \
  --openssf-commit OPENSSF_40_HEX_COMMIT \
  --base-snapshot /tmp/base-snapshot.json \
  --snapshot-version YYYY-MM-DD.N \
  --output /tmp/candidate.json \
  --corrections /tmp/corrections.json
```

GitHub/OSV aliases are merged before package identity is considered, preventing
the same advisory from becoming duplicate records. Exact OSV version lists are
retained as exact `= VERSION` entries. Only open-ended ecosystem ranges are
retained; bounded ranges that the scanner cannot represent are omitted, leaving
package identity as an unconfirmed signal unless exact versions are supplied.
Withdrawn, rejected, `not_affected`, and false-positive records are omitted
and recorded in the corrections ledger. Each active record
retains its selected primary source, source URL, aliases, dates, affected scope,
and all contributing source URLs.

The candidate retains the reviewed package and file-hash records from the
supplied base snapshot, including Axios's exact affected versions. The script
uses local Git to verify that each OpenSSF JSON file matches a regular blob in
the supplied commit. The maintainer must still verify that this commit belongs
to the intended OpenSSF repository. Review the source pins and corrections,
validate the candidate with the Repyy tests, and only then update the embedded source. Signing remains in
the protected release workflow. Never place the signing private key in this
workflow or repository.

## Review boundaries

- Do not add `rest-icon-orchestrator` without primary evidence.
- Preserve Axios as two exact records: `1.14.1` and `0.30.4`.
- A safe exact lock version must not become confirmed merely because a manifest
  range could select a compromised version.
- Do not turn a withdrawn or corrected report into a name-only warning.
- Never fetch advisory data during a scan, request an indicator URL, or infer a
  domain/package relationship from campaign proximity.
