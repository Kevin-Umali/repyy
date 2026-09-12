# repyy landing page concepts

Three standalone directions and a documentation site are included:

- `index.html`: Forensic Calm, a bright silver product story.
- `variant-b.html`: Threat Cutaway, a darker and more editorial alternative.
- `variant-c.html`: Repository Autopsy, a hard-edged safety-orange direction.
- `docs.html`: searchable installation, usage, trust-model, and CLI reference.

Preview them from the repository root:

```sh
python3 -m http.server 4173 -d site
```

Then open `http://localhost:4173`.

The pages use no package manager or runtime dependency. Shared behavior lives in
`site.js`, shared styling lives in `styles.css`, and generated WebP campaign
imagery lives under `assets/`.
