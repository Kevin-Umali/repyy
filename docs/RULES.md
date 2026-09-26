# Built-in behavioral rule reference

The [/rules/ reference](https://repyy.dev/rules/) is generated from Repyy's
versioned `BuiltinRuleCatalog`. Use `repyy rules catalog --format json` for the
same machine-readable catalog or `repyy rules explain RULE-ID` for one rule.

Each entry gives the category, base severity and confidence, disposition,
description, rationale, common legitimate use, remediation, match scope,
applicable paths, and whether file context may downgrade it. Scanner reports
record the built-in ruleset version. A rule match still requires review of the
source and its use.

`repyy rules list --format json` is the separate, dated package and file-hash
intelligence snapshot. Advisory-specific `IOC-PKG-*` IDs are explained from the
active snapshot, while this behavioral catalog contains their rule family.

`site/src/data/rule-catalog.json` is a generated copy of the behavioral catalog
for Astro's static build. It is not an intelligence snapshot or a second source
of advisory data. The Go catalog and CLI export remain authoritative.

To refresh the checked-in website data after changing rules, run:

```sh
go run ./cmd/repyy rules catalog --format json > site/src/data/rule-catalog.json
cd site && npx prettier --write src/data/rule-catalog.json
```

The catalog and site checks verify the generated data and route links.
