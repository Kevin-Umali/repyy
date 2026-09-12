# repyy website

The canonical landing page and documentation site are:

- `index.html`: the product site for take-home and interview repository review.
- `docs.html`: searchable installation, usage, trust-model, and CLI reference.

Preview them from the repository root:

```sh
python3 -m http.server 4173 -d site
```

Then open `http://localhost:4173`.

The pages use no package manager or runtime dependency. Shared behavior lives in
`site.js`; index-only interaction lives in `landing.js`. The two pages keep their
styles in `landing.css` and `docs.css`.
