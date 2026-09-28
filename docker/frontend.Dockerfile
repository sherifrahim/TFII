# ── Stage 1: Build React app ──────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# package.json is tracked in the repo (react, react-dom, react-scripts only)
COPY frontend/package.json ./package.json
COPY frontend/public ./public
COPY frontend/src    ./src

RUN npm install --legacy-peer-deps

# Inject the API domain at build time
ARG DOMAIN=localhost
# (config.js falls back to the page origin if this is ever skipped)
RUN sed -i "s|YOUR_DOMAIN|${DOMAIN}|g" src/config.js

RUN GENERATE_SOURCEMAP=false npm run build

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
