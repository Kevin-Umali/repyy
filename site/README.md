# repyy website

The canonical landing page and documentation site are:

- `index.html`: the silver and cobalt product site for take-home and interview repository review.
- `docs.html`: searchable installation, usage, trust-model, and CLI reference.

Two earlier design studies remain available for reference:

- `variant-b.html`: Threat Cutaway.
- `variant-c.html`: Repository Autopsy.

Preview them from the repository root:

```sh
python3 -m http.server 4173 -d site
```

Then open `http://localhost:4173`.

The pages use no package manager or runtime dependency. Shared behavior lives in
`site.js`, shared styling lives in `styles.css`, and generated WebP campaign
imagery lives under `assets/`.
