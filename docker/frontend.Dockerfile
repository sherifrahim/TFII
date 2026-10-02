# ── Stage 1: Build React app ──────────────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

# Build inputs, with the lockfile so the build uses the exact versions that were tested
COPY frontend/package.json frontend/package-lock.json ./
COPY frontend/vite.config.js frontend/index.html ./
COPY frontend/public ./public
COPY frontend/src    ./src

RUN npm ci

# No API address is baked in: the UI is served from the same origin as the API (nginx proxies everything
# that is not /ui/ to the backend), and config.js falls back to the page's own origin. That works for
# http://localhost, an IP address with a port, or https://your-domain alike. (Substituting a domain here used
# to hard-code https://, which broke the plain-HTTP local setup: the UI loaded but login could not connect.)

# (source maps are off in vite.config.js)
RUN npm run build

# ── Stage 2: Serve with nginx ─────────────────────────────────────────────────
FROM nginx:1.25-alpine

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

COPY docker/nginx/app.conf /etc/nginx/conf.d/app.conf
COPY docker/nginx/security-headers.conf /etc/nginx/snippets/tfii-security-headers.conf

# Copy React build to nginx html dir
COPY --from=builder /app/build /usr/share/nginx/html/ui

# Nginx runs as non-root
RUN chown -R nginx:nginx /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
