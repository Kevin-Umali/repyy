# About Repyy

Reviewed: 2026-09-15.

I use Repyy myself to inspect unfamiliar repositories before running them.

The idea grew out of reading many LinkedIn posts about risky take-home assignments and developers
being asked to run unfamiliar code. Those posts made a familiar workflow worth questioning: receive
a repository, install its dependencies, and start working before looking at what might execute.

Repyy adds a review step before that first install, startup command, or IDE open. It gives me files
and patterns to inspect, with the limits of that inspection kept visible.

The [project repository](https://github.com/Kevin-Umali/repyy) contains the source, contribution
history and maintainer context.

## Project principles

Read assignment contents as untrusted data. Report evidence and uncertainty. Keep incomplete
coverage visible. Keep private source and reports local during scans. Prefer regression coverage and
verifiable releases over expanding rule counts.

Repyy identifies risks. It cannot prove that a repository is safe.

## Security reporting

Please use
[private vulnerability reporting](https://github.com/Kevin-Umali/repyy/security/advisories/new) for
defects in Repyy. Include the version and smallest inert reproduction. The
[security policy](../SECURITY.md) explains the reporting process. Ordinary feedback and false
positives can use the public issue templates after checking for sensitive content.

Read [Trust and Limitations](TRUST.md) and [Security Testing](SECURITY-TESTING.md) before relying on
the scanner's results.
