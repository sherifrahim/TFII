import { defineConfig, transformWithOxc } from "vite";
import react from "@vitejs/plugin-react";

// The app is served as static files under /ui/ (nginx), next to the API on the same origin.
// Output keeps the layout the server config relies on: build/index.html plus content-hashed
// files under build/static/ (nginx caches /ui/static/ for a year, and the "new version
// available" check reads the main bundle's name from index.html).
export default defineConfig({
  base: "/ui/",
  plugins: [
    // The source files are .js and contain JSX: compile them as JSX before the default transform sees them.
    { name: "js-as-jsx", enforce: "pre", transform: (code, id) => (/\/src\/.*\.js$/.test(id) ? transformWithOxc(code, id, { lang: "jsx" }) : null) },
    react(),
  ],
  build: {
    outDir: "build",
    emptyOutDir: true,
    sourcemap: false,               // never publish source maps
    assetsInlineLimit: 0,           // no data: URIs from the bundler; the CSP allows them for fonts only
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: {
        entryFileNames: "static/js/main.[hash].js",
        chunkFileNames: "static/js/[name].[hash].js",
        assetFileNames: "static/[ext]/[name].[hash][extname]",
      },
    },
  },
  server: { port: 3000, proxy: { "/api": "http://localhost:8000" } },
  test: { environment: "jsdom", globals: true, include: ["src/**/*.test.js"] },
});
