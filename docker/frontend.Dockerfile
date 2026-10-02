# ── Stage 1: Build React app ──────────────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

# Build inputs, with the lockfile so the build uses the exact versions that were tested
COPY frontend/package.json frontend/package-lock.json ./
COPY frontend/vite.config.js frontend/index.html ./
COPY frontend/public ./public
COPY frontend/src    ./src

RUN npm ci

# Inject the API domain at build time
ARG DOMAIN=localhost
# (config.js falls back to the page origin if this is ever skipped)
RUN sed -i "s|YOUR_DOMAIN|${DOMAIN}|g" src/config.js

# (source maps are off in vite.config.js)
RUN npm run build

# ── Stage 2: Serve with nginx ─────────────────────────────────────────────────
FROM nginx:1.25-alpine

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

COPY docker/nginx/app.conf /etc/nginx/conf.d/app.conf

# Copy React build to nginx html dir
COPY --from=builder /app/build /usr/share/nginx/html/ui

# Nginx runs as non-root
RUN chown -R nginx:nginx /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
