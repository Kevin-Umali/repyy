"""Check static documentation links and the bundled cross-page search index."""

import ast
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit


SITE = Path(__file__).resolve().parent
GUIDES = {
    "docs.html",
    "installation.html",
    "cli.html",
    "configuration.html",
    "isolation.html",
    "coverage.html",
    "intelligence.html",
    "agent-skill.html",
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


def main():
    pages = {}
    errors = []
    for path in SITE.glob("*.html"):
        page = Page()
        page.feed(path.read_text(encoding="utf-8"))
        pages[path.resolve()] = page
        for ident, count in Counter(page.ids).items():
            if count > 1:
                errors.append(f"{path.name}: duplicate id #{ident}")

    for path, page in pages.items():
        for reference in page.references:
            url = urlsplit(reference)
            if url.scheme or url.netloc:
                continue
            destination = (path.parent / unquote(url.path)).resolve() if url.path else path
            if not destination.exists():
                errors.append(f"{path.name}: missing {reference}")
            elif url.fragment and destination.suffix == ".html":
                target = pages.get(destination)
                if target is None or unquote(url.fragment) not in target.ids:
                    errors.append(f"{path.name}: missing anchor {reference}")

    script = (SITE / "site.js").read_text(encoding="utf-8")
    match = re.search(r"const docsGlobalIndex = (\[.*?\n\]);", script, re.S)
    if not match:
        errors.append("site.js: missing bundled documentation search index")
        entries = []
    else:
        entries = ast.literal_eval(match.group(1))
    indexed = set()
    for entry in entries:
        if len(entry) != 5:
            errors.append(f"search index: malformed entry {entry!r}")
            continue
        filename, _, ident, _, _ = entry
        key = (filename, ident)
        if key in indexed:
            errors.append(f"search index: duplicate {filename}#{ident}")
        indexed.add(key)
        target = pages.get((SITE / filename).resolve())
        if filename not in GUIDES or target is None or ident not in target.ids:
            errors.append(f"search index: missing {filename}#{ident}")
    for filename in GUIDES:
        page = pages.get((SITE / filename).resolve())
        if page is None:
            errors.append(f"missing guide {filename}")
            continue
        for ident in page.searchable:
            if (filename, ident) not in indexed:
                errors.append(f"search index: unindexed {filename}#{ident}")

    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Checked {len(pages)} HTML pages and {len(entries)} search destinations")


if __name__ == "__main__":
    main()
