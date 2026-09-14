# Trusted configuration

Configuration is opt-in. A repository cannot weaken its own scan with a repository-owned
`.repyy.yaml`; pass a file you have reviewed with `--config PATH`.

## Minimal file

The file must use version `1`:

```yaml
version: 1
rules: []
suppressions: []
```

Validate before scanning:

```sh
repyy rules validate my-repyy.yaml
repyy scan ./checkout --config my-repyy.yaml
```

## Add a custom rule

Custom rules are declarative regular-expression matches. They cannot execute commands. Required
fields are `id`, `category`, `severity`, `confidence`, `description`, and `pattern`. `globs` limits
matching to file names or paths using case-insensitive comparisons; `match_scope` defaults to `raw`
and may be `raw` or `code` for custom rules. `structured` is reserved for built-in structured
detectors and is rejected in a custom configuration. Optional `remediation`, `rationale`,
`legitimate_use`, `disposition`, and `allow_context_downgrade` provide review context.

```yaml
version: 1
rules:
  - id: ORG-001
    category: credential-harvesting
    severity: high
    confidence: medium
    description: Reads the organization's private token file
    pattern: '(?i)\.config/acme/token'
    globs: ["*.js", "*.ts", "*.py"]
    remediation: Confirm the access is required and remove secrets from source.
    rationale: This path contains credentials on developer machines.
    legitimate_use: A documented security tool may read this file intentionally.
    disposition: review
    match_scope: code
```

Valid severity values are `low`, `medium`, `high`, and `critical`. Confidence is `low`, `medium`, or
`high`. Disposition is `informational`, `harden`, `review`, or `block` and only changes
presentation.

## Suppress one reviewed finding

Suppressions use the finding's stable fingerprint. Copy the fingerprint from a JSON scan report,
record why it is acceptable, and add an optional ISO date expiry (`YYYY-MM-DD`):

```yaml
version: 1
suppressions:
  - fingerprint: "sha256:replace-with-report-fingerprint"
    reason: "Reviewed internal fixture; no executable path."
    expires: "2026-12-31"
```

Every suppression needs a fingerprint and reason. Expired suppressions stop being active
automatically. Suppressions do not remove the underlying rule or change unrelated findings.

Keep this file outside untrusted repositories when possible, and review changes to it like code.
`repyy rules validate` checks YAML, version, rule fields, regular expressions, and suppression dates
without scanning a target.
