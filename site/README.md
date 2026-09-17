# repyy website

The product site and documentation are an Astro static site. The production build has no server runtime, framework integration, CMS, or client-side component runtime.

## Local development

Use the Node version declared in `.nvmrc`, then install the locked dependencies:

```sh
nvm use
npm ci
npm run dev
```

The usual checks are:

```sh
npm run check
npm run format:check
npm run build
python3 check_docs.py
npm run preview
```

Run those commands from `site/`. Equivalent `site-*` targets are available in the repository Makefile.

Page routes live in `src/pages/`. Reusable site chrome lives in `src/components/` and `src/layouts/`; typed guide metadata and navigation order live in `src/data/guides.ts`. Shared browser behavior is split by concern under `src/scripts/`. The build creates `dist/search-index.json` from rendered searchable sections.

The files under `public/demo/sample/` are generated review artifacts. Their inline CSS and JavaScript are protected by Content Security Policy hashes. Do not format or hand-edit them; `check_docs.py` verifies the hashes in the built copy.
