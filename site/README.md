# repyy website

The canonical landing page and documentation site are:

- `index.html`: the product site for take-home and interview repository review.
- `docs/index.html`: the documentation hub with a first scan, result overview, and links to the
  detailed guides.
- `installation/index.html`, `cli/index.html`, `configuration/index.html`, `isolation/index.html`,
  `coverage/index.html`, `intelligence/index.html`, and `agent-skill/index.html`: complete web
  guides for people using the site. This directory-index layout keeps public URLs clean, such as
  `/docs/` and `/coverage/#map`, when deployed with Dokploy Static. The files in `docs/` are the
  detailed offline counterparts for repository readers and should stay aligned with behavior.

Preview them from the repository root:

```sh
python3 -m http.server 4173 -d site
```

Then open `http://localhost:4173`, `http://localhost:4173/docs/`, or
`http://localhost:4173/coverage/#map`.

The pages use no package manager or runtime dependency. Shared behavior lives in `site.js`;
index-only interaction lives in `landing.js`. The landing page uses `landing.css`; all documentation
pages share `docs.css`. Basic navigation and links work with JavaScript disabled; scripts add
search, copy buttons, and scroll state.

Trust and evidence pages use the same `docs.css` and `site.js` shell: `trust/`, `verification/`,
`demo/`, `security-testing/`, and `about/`. Keep their Markdown counterparts under `docs/` (and
`demo/README.md`) aligned. Public samples under `demo/sample/` are generated only from the reviewed
inert fixture corpus using `scripts/benchmark.py`; never place private scan reports there.

Run `python3 site/check_docs.py` after editing pages or the bundled search index.
