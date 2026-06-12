# ── Stage 1: Build React app ──────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files first (layer cache — only rebuilds if deps change)
COPY frontend/public ./public
COPY frontend/src    ./src

# Create package.json for the build
# (repo stores source only; package.json lives on the host server)
# We provide a minimal one here
RUN cat > package.json << 'EOF'
{
  "name": "threatfeed-ui",
  "version": "0.1.0",
  "private": true,
  "homepage": "/ui/",
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-scripts": "5.0.1",
    "web-vitals": "^2.1.4"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build"
  },
  "browserslist": {
    "production": [">0.2%", "not dead", "not op_mini all"],
    "development": ["last 1 chrome version", "last 1 firefox version"]
  }
}
EOF

RUN npm install --legacy-peer-deps

# Inject the API domain at build time
ARG DOMAIN=localhost
RUN sed "s|YOUR_DOMAIN|${DOMAIN}|g" src/App.js > /tmp/App.js && mv /tmp/App.js src/App.js

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
