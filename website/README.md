# scan4secrets website

Docusaurus 3 site for scan4secrets. Published to `https://scan4secrets.m14r41.in`.

## Develop

```bash
bun install
bun start
```

## Build

```bash
bun run build
bun run serve
```

## Deploy

Pushes to `main` build and deploy via `.github/workflows/docs-deploy.yml` to the `gh-pages` branch. GitHub Pages serves it on the CNAME domain in `static/CNAME`.
