"""Validate the built Astro site, documentation links, search data, and samples."""

import base64
from collections import Counter
import hashlib
from html import unescape
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit


SITE = Path(__file__).resolve().parent
DIST = SITE / "dist"
REPOSITORY = SITE.parent
GUIDES = {
    "/docs/": ["README.md"],
    "/installation/": ["docs/INSTALLATION.md"],
    "/cli/": ["docs/CLI.md"],
    "/configuration/": ["docs/CONFIGURATION.md"],
    "/isolation/": ["docs/SANDBOX.md", "docs/VM-GUIDES.md"],
    "/coverage/": ["docs/COVERAGE.md"],
    "/rules/": ["docs/RULES.md"],
    "/intelligence/": [],
    "/agent-skill/": ["skills/repyy/SKILL.md"],
    "/trust/": ["docs/TRUST.md"],
    "/demo/": ["demo/README.md"],
    "/verification/": ["docs/VERIFICATION.md"],
    "/security-testing/": ["docs/SECURITY-TESTING.md"],
    "/about/": ["docs/ABOUT.md"],
}
EXPECTED_ROUTES = {"/", *GUIDES}
EXPECTED_ARTIFACTS = {
    "/demo/sample/sample.html",
    "/demo/sample/sample.json",
    "/demo/sample/sample.txt",
    "/demo/sample/results.json",
    "/demo/sample/results.md",
    "/search-index.json",
}


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.searchable = set()
        self.references = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        ident = attributes.get("id")
        if ident:
            self.ids.append(ident)
            if "docs-searchable" in attributes.get("class", "").split():
                self.searchable.add(ident)
        for key in ("href", "src"):
            if attributes.get(key):
                self.references.append(attributes[key])


def route_file(route):
    return (
        DIST / route.lstrip("/") / "index.html" if route != "/" else DIST / "index.html"
    )


def main():
    if not DIST.is_dir():
        raise SystemExit("site/dist is missing; run `npm run build` in site first")

    pages = {}
    errors = []
    for path in DIST.rglob("*.html"):
        page = Page()
        page.feed(path.read_text(encoding="utf-8"))
        pages[path.resolve()] = page
        for ident, count in Counter(page.ids).items():
            if count > 1:
                errors.append(f"{path.relative_to(DIST)}: duplicate id #{ident}")

    for route in EXPECTED_ROUTES:
        if not route_file(route).is_file():
            errors.append(f"missing route {route}")
    for artifact in EXPECTED_ARTIFACTS:
        if not (DIST / artifact.lstrip("/")).is_file():
            errors.append(f"missing artifact {artifact}")
    for route, counterparts in GUIDES.items():
        for counterpart in counterparts:
            if not (REPOSITORY / counterpart).is_file():
                errors.append(f"{route}: missing Markdown counterpart {counterpart}")

    for path, page in pages.items():
        for reference in page.references:
            url = urlsplit(reference)
            if url.scheme or url.netloc or reference.startswith(("mailto:", "data:")):
                continue
            if url.path.startswith("/"):
                destination = (DIST / unquote(url.path).lstrip("/")).resolve()
            elif url.path:
                destination = (path.parent / unquote(url.path)).resolve()
            else:
                destination = path
            if destination.is_dir():
                destination = destination / "index.html"
            if not destination.exists():
                errors.append(f"{path.relative_to(DIST)}: missing {reference}")
            elif url.fragment:
                target = pages.get(destination.resolve())
                if target is None or unquote(url.fragment) not in target.ids:
                    errors.append(
                        f"{path.relative_to(DIST)}: missing anchor {reference}"
                    )

    report = (DIST / "demo/sample/sample.html").read_text(encoding="utf-8")
    for tag in ("style", "script"):
        for body in re.findall(rf"<{tag}[^>]*>(.*?)</{tag}>", report, re.S):
            digest = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
            if f"sha256-{digest}" not in unescape(report):
                errors.append(f"sample.html: {tag} content does not match its CSP hash")

    try:
        entries = json.loads((DIST / "search-index.json").read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        errors.append(f"search index: {error}")
        entries = []
    indexed = set()
    for entry in entries:
        required = {"route", "pageTitle", "id", "title", "text"}
        if not isinstance(entry, dict) or set(entry) != required:
            errors.append(f"search index: malformed entry {entry!r}")
            continue
        key = (entry["route"], entry["id"])
        if key in indexed:
            errors.append(f"search index: duplicate {entry['route']}#{entry['id']}")
        indexed.add(key)
        target = pages.get(route_file(entry["route"]).resolve())
        if (
            entry["route"] not in GUIDES
            or target is None
            or entry["id"] not in target.ids
        ):
            errors.append(f"search index: missing {entry['route']}#{entry['id']}")
    for route in GUIDES:
        page = pages.get(route_file(route).resolve())
        if page:
            for ident in page.searchable:
                if (route, ident) not in indexed:
                    errors.append(f"search index: unindexed {route}#{ident}")

    try:
        catalog = json.loads((SITE / "src/data/rule-catalog.json").read_text(encoding="utf-8"))
        rule_ids = [rule["id"] for rule in catalog["rules"]]
        if catalog["schema_version"] != "1" or len(rule_ids) != len(set(rule_ids)):
            errors.append("rule catalog: invalid schema or duplicate IDs")
        source = (REPOSITORY / "internal/scan/builtin.go").read_text(encoding="utf-8")
        version = re.search(r'BuiltinRulesVersion = "([^"]+)"', source)
        if not version or version.group(1) != catalog["rules_version"]:
            errors.append("rule catalog: ruleset version differs from scanner")
        rules_html = route_file("/rules/").read_text(encoding="utf-8")
        coverage_html = route_file("/coverage/").read_text(encoding="utf-8")
        rendered = re.findall(r'<section class="[^"]*rule-entry" id="rule-([A-Za-z0-9*_-]+)"', rules_html)
        linked = re.findall(r'href="/rules/#rule-([A-Za-z0-9*_-]+)"', coverage_html)
        if Counter(rendered) != Counter(rule_ids):
            errors.append("rule reference: rendered IDs do not match catalog exactly")
        if Counter(linked) != Counter(rule_ids):
            errors.append("coverage map: linked IDs do not match catalog exactly")
        if catalog["rules_version"] not in rules_html or catalog["rules_version"] not in coverage_html:
            errors.append("rule reference: rendered ruleset version missing")
        if {entry["id"] for entry in entries if entry["route"] == "/rules/" and entry["id"].startswith("rule-")} != {"rule-" + ident for ident in rule_ids}:
            errors.append("rule reference: catalog entries missing from search")
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        errors.append(f"rule catalog: {error}")

    if errors:
        raise SystemExit("\n".join(errors))
    print(
        f"Checked {len(EXPECTED_ROUTES)} routes, {len(entries)} search destinations, and {len(EXPECTED_ARTIFACTS)} artifacts"
    )


if __name__ == "__main__":
    main()
