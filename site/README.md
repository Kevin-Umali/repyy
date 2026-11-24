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

## Production deployment on Dokploy

Repyy’s public site consists of Astro pages, a static search index, images, and sample reports.
Search runs in the browser. The site has no login, uploads, or API request handlers. The build
emits a Content Security Policy with hashes for Astro's bundled scripts and styles. Inline style
attributes are allowed for the SVG illustrations. The sample HTML report has its own policy.

### Deploy the site

1. In Dokploy, use `/site` as the build path and select Nixpacks. Install the locked dependencies
   with `npm ci --include=dev` if the build environment omits dev dependencies. Build with
   `npm run build` and set the publish directory to `dist`. The [Dokploy build type guide](https://docs.dokploy.com/docs/core/applications/build-type)
   explains how it serves the output through Nginx.
2. In Dynadot, point the domain's A record at the Dokploy host. Add an AAAA record only if the host
   serves the site over IPv6.
3. Route the domain to container port `80` in Dokploy. Enable HTTPS and choose Let's Encrypt.
   The domain route uses the Docker network, so the application container needs no separate
   published host port. [Dokploy domain setup](https://docs.dokploy.com/docs/core/domains/others)

### HTTP response headers

In the app's Traefik File System, add this middleware and append `repyy-headers` to the site's
HTTPS router. Keep the generated router rules, TLS configuration, and existing middlewares.

```yaml
http:
  middlewares:
    repyy-headers:
      headers:
        contentTypeNosniff: true
        frameDeny: true
        referrerPolicy: strict-origin-when-cross-origin
        permissionsPolicy: "camera=(), microphone=(), geolocation=()"
```

After confirming working HTTPS and the HTTP redirect, set `stsSeconds: 31536000` in the same
middleware. The main site and sample report carry separate HTML policies. Preserve both when
configuring Traefik. [Dokploy hardening guide](https://docs.dokploy.com/docs/core/guides/production-hardening)

Keep Nginx serving the published files and returning 404 for missing paths. If request volume
affects availability, add Traefik rate limiting to the public HTTPS router and tune it against
normal page and asset loads. Use the connection's source address for this direct-to-Traefik
deployment. [Dokploy rate limiting](https://docs.dokploy.com/docs/core/guides/production-hardening#config-snippets)

### Verify after deploying

- Check that HTTP redirects to HTTPS, the certificate covers the domain, and ordinary pages and
  `/search-index.json` return 200.
- Inspect an HTTPS response for `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and
  `Permissions-Policy`. Check `Strict-Transport-Security` once enabled.
- Request a nonexistent path such as `/__missing_page` and expect 404.
- Open the docs, search for a guide, and open the sample report. The browser console should show
  no Content Security Policy violations.
