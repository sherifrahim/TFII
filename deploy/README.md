# Deploy

The live server (`threatintel.mooo.com`) runs **natively, not in Docker** — the
`docker/` directory and `docker-compose.yml` describe a different, unused path.
What actually runs:

| Piece | Location on server |
|---|---|
| Frontend (static) | `/home/ubuntu/threatfeed-ui/build/` served by nginx |
| Backend | `/home/ubuntu/threatfeed/` via `threatfeed.service` (uvicorn on 127.0.0.1:8000) |
| Database | PostgreSQL 14, native (`postgresql@14-main.service`) |
| nginx site | `/etc/nginx/sites-available/threatfeed` — tracked here as `nginx/threatfeed.conf` |

`nginx/threatfeed.conf` is a copy of the running config. It lives here so the
cache rules and SPA fallback survive the box being rebuilt. If you change it on
the server, copy it back.

## What ships

| Piece | Source in repo | Notes |
|---|---|---|
| Backend | `backend/*.py` | `main.py` imports `intel_api.py` (the `/v2/*` API). Always deploy every `*.py` together. |
| Frontend | `frontend/src/**` | Entry `App.js` → `Root.js`; pages in `pages/`, shell in `shell/`, the original tools in `legacy/`. Only `react`/`react-dom`/`react-scripts` are required. |

Schema changes are additive and applied automatically at startup
(`intel_api.ensure_schema`): new tables `investigations`, `investigation_items`,
`investigation_events`, `ioc_provenance`, new columns `iocs.last_seen` and
`admin_notes.investigation_id`, and indexes on the IOC/CVE tables. Nothing is
dropped or rewritten, so rolling back the code leaves a working database.

## Automated deploy (push to master)

`.github/workflows/deploy.yml` builds the UI on the GitHub Actions runner,
checks the backend compiles, uploads one release tarball, then on the server:
installs requirements, swaps in `backend/*.py` (backup in `~/backend.pre-*`,
automatic rollback if `/health` fails after restart) and swaps the UI build
(previous one kept as `build.old`). Nothing is compiled on the server.

## Never build the frontend on the server

The host has **~956MB RAM**. `npm run build` exhausts it and wedges the whole
machine — TCP keeps accepting while userspace stops responding, and it does not
self-recover. `react-scripts` also empties `build/` *before* compiling, so a
killed build leaves no site at all.

Build locally and ship the artifact:

```bash
# 1. build locally (frontend/package.json + package-lock.json are tracked)
cd frontend && npm ci --legacy-peer-deps
sed -i "s|YOUR_DOMAIN|threatintel.mooo.com|" src/config.js   # optional: config.js
                                                                # falls back to the page origin
GENERATE_SOURCEMAP=false npm run build
git checkout src/config.js
```

`GENERATE_SOURCEMAP=false` matters — production has never shipped `.map` files
and they would expose the full frontend source on a public site.

```bash
# 2. ship, staged so rollback is one mv
tar czf ui-build.tar.gz build
scp ui-build.tar.gz ubuntu@<host>:/tmp/
```

```bash
# 3. on the server: verify the stage, then swap
rm -rf /tmp/stage && mkdir -p /tmp/stage && tar xzf /tmp/ui-build.tar.gz -C /tmp/stage \
  && test -f /tmp/stage/build/index.html \
  && sudo chown -R root:root /tmp/stage/build \
  && sudo rm -rf ~/threatfeed-ui/build.old \
  && sudo mv ~/threatfeed-ui/build ~/threatfeed-ui/build.old \
  && sudo mv /tmp/stage/build ~/threatfeed-ui/build
```

Rollback: `sudo rm -rf ~/threatfeed-ui/build && sudo mv ~/threatfeed-ui/build.old ~/threatfeed-ui/build`

## Backend

Compile with the service's own interpreter *before* swapping, and roll back if
health fails:

```bash
# upload backend/*.py to /tmp/tfii-backend/ first
cd ~/threatfeed && mkdir -p ~/backend.pre-$(date +%Y%m%d-%H%M%S) && cp *.py ~/backend.pre-*/ \
  && venv/bin/python -m py_compile /tmp/tfii-backend/*.py \
  && cp /tmp/tfii-backend/*.py . \
  && sudo systemctl restart threatfeed && sleep 6 \
  && curl -sf http://127.0.0.1:8000/health && echo OK || echo "FAILED — restore from ~/backend.pre-*"
```

## Caching

`index.html` is served `no-cache` (revalidated, cheap 304) and `/ui/static/*` is
`immutable` for a year. This pairing is what makes deploys safe: those static
filenames are content-hashed, so they can be cached forever, while a stale
`index.html` would point at hashed bundles that no longer exist — a blank app,
not merely a missing feature.
