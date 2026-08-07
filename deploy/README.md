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

## Never build the frontend on the server

The host has **~956MB RAM**. `npm run build` exhausts it and wedges the whole
machine — TCP keeps accepting while userspace stops responding, and it does not
self-recover. `react-scripts` also empties `build/` *before* compiling, so a
killed build leaves no site at all.

Build locally and ship the artifact:

```bash
# 1. build (locally, with the server's own package.json / package-lock.json)
GENERATE_SOURCEMAP=false npm run build
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
cd ~/threatfeed && cp main.py ~/main.py.pre-$(date +%Y%m%d-%H%M%S) \
  && venv/bin/python -m py_compile /tmp/main.py.new \
  && cp /tmp/main.py.new main.py \
  && sudo systemctl restart threatfeed && sleep 6 \
  && curl -sf http://127.0.0.1:8000/health && echo OK || echo "FAILED — restore ~/main.py.pre-*"
```

## Caching

`index.html` is served `no-cache` (revalidated, cheap 304) and `/ui/static/*` is
`immutable` for a year. This pairing is what makes deploys safe: those static
filenames are content-hashed, so they can be cached forever, while a stale
`index.html` would point at hashed bundles that no longer exist — a blank app,
not merely a missing feature.
