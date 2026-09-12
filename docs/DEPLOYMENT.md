# Deploy the website with Dokploy

The website in `site/` is static HTML, CSS, JavaScript, and image assets. It does not need a Node build, a backend, or a long-running application process of its own.

## Recommended setup

1. Connect this GitHub repository to Dokploy.
2. Create an **Application** and select the **Static** build type.
3. Set the branch to `main`.
4. Set the root or build path to `/site`.
5. Leave the publish directory empty.
6. Expose port `80` and attach the domain.
7. Enable HTTPS through Dokploy and Traefik.
8. Enable automatic deployment on push, or keep production deployment manual if you want to review CI first.

Dokploy packages a static application into an optimized NGINX container. One lightweight service is enough; do not create a separate backend instance for this site.

## Deployment flow

```text
feature branch -> pull request -> CI -> merge to main -> Dokploy deploy
```

The repository CI smoke-tests the required pages, styles, script, and hero asset. No additional frontend build command is required.

Manual drag-and-drop is useful for a temporary preview, but it should not be the production workflow. A Git-backed deployment is repeatable, auditable, and easy to redeploy.

## Local preview

```sh
python3 -m http.server 4173 --directory site
```

Open `http://127.0.0.1:4173/`.

## Dokploy references

- [Static build type](https://docs.dokploy.com/docs/core/applications/build-type)
- [Deploy HTML](https://docs.dokploy.com/docs/core/html)
- [GitHub integration](https://docs.dokploy.com/docs/core/github)
