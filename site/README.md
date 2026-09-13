# repyy website

The canonical landing page and documentation site are:

- `index.html`: the product site for take-home and interview repository review.
- `docs.html`: the documentation hub with a first scan, result overview, and
  links to the detailed guides.
- `installation.html`, `cli.html`, `configuration.html`, `isolation.html`,
  `coverage.html`, `intelligence.html`, and `agent-skill.html`: complete web
  guides for people using the site. The files in `docs/` are the detailed
  offline counterparts for repository readers and should stay aligned with behavior.

Preview them from the repository root:

```sh
python3 -m http.server 4173 -d site
```

Then open `http://localhost:4173`.

The pages use no package manager or runtime dependency. Shared behavior lives in
`site.js`; index-only interaction lives in `landing.js`. The landing page uses
`landing.css`; all documentation pages share `docs.css`. Basic navigation and
links work with JavaScript disabled; scripts add search, copy buttons, and
scroll state.
