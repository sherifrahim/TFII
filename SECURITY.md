# Security policy

TFII is a security tool that stores API keys and handles untrusted data (indicators, feed content, URLs), so
security reports are welcome and taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository
(<https://github.com/sherifrahim/TFII/security/advisories/new>). Include what you found, how to reproduce it, and
the version or commit. You will get an acknowledgement, and we will keep you informed while it is fixed.

If private reporting is not available to you, open an issue that says only "security report, please contact me"
without details, and a maintainer will reach out.

## What is in scope

* Authentication, sessions and the role/capability model (`admin`, `analyst`, `explorer`)
* Anything that lets one user read, use or overwrite another user's stored API keys
* SSRF, injection, XSS, path traversal or unsafe deserialisation in the API or the UI
* Secrets in logs, responses or the repository

## How the project handles security today

* There is **no default password**: the first admin password is set with `ADMIN_INITIAL_PASSWORD` or generated
  randomly and shown once at first start.
* Stored API keys are encrypted at rest (Fernet, `ENCRYPTION_KEY`); a key is only shown or tested for its owner.
* Outbound fetches of third-party URLs go through an SSRF-safe client that vets the address at connect time.
* The API and the UI send restrictive security headers (CSP, `nosniff`, frame denial).
* Route authorization is covered by an automated test that fails if a new route is added without auth.
* Every change runs the test suite in CI; see [docs/INTELLIGENCE_CORE.md](docs/INTELLIGENCE_CORE.md#security-baseline)
  for the model and its known limitations.

## Dependency alerts

Dependabot flags known-vulnerable packages. This is the state of them, checked with `npm audit` and `pip-audit` on
2026-10-01. Some alerts remain open on purpose; "not reachable" below means the package is not part of what runs in
production, not that it is free of risk to people who build or develop TFII.

**What ships.** The production image serves a static bundle (react, react-dom, the app's own code) from nginx. The
React toolchain (`react-scripts` 5.0.1, the last release of Create React App, which is no longer maintained) runs
only in the Docker build stage, on `npm start`, and in the tests. None of it is in the image that serves users.

**Fixed.** `serialize-javascript`, `bfj` / `jsonpath` / `underscore` and `uuid` are raised through `overrides` in
`frontend/package.json` (the toolchain pins the old versions, and `react-scripts` has no newer release to upgrade
to). Lint, unit tests and the production build pass with them. The `serialize-javascript` bump in
`rollup-plugin-terser` is not exercised by this build (the app has no service worker), so it is untested.

**Remaining, backend (`backend/requirements.txt`).**

* `ecdsa` (via `python-jose`), Minerva timing side channel, [CVE-2024-23342](https://github.com/advisories/GHSA-wj6h-64fc-37mp):
  no fixed version exists and the maintainers do not plan one. The API signs its tokens with HS256 only and never
  uses ECDSA, so the vulnerable code path is not used. Replacing `python-jose` with PyJWT would remove the package.

**Remaining, frontend (`frontend/package-lock.json`), build, dev or test time only.**

* `webpack-dev-server`, `webpack-dev-middleware`: affect the local `npm start` server only (for example, source
  exposure if you open a malicious site while it runs). The fix needs webpack-dev-server 5, which Create React App
  does not support. If you run `npm start`, do so on a trusted network and do not browse other sites meanwhile.
* `postcss` 7 and `resolve-url-loader`: used only for Sass; this app has no Sass files.
* `svgo`, `@svgr/webpack`, `@svgr/plugin-svgo`, `nth-check`, `css-select`: used only to turn SVG imports into
  components; the app imports none. A newer `svgo` or `nth-check` has an incompatible API, so overriding would break
  the build rather than fix it.
* `jest`, `jsdom`, `@tootallnate/once`, `http-proxy-agent` (low severity): test runner only.

The real fix for the frontend remaining items is moving off Create React App (for example to Vite); that is a larger
change and is not part of this pass. GitHub's alert count (21) does not match `npm audit`'s package count (19 left)
because the two count differently; compare by advisory id, not by number.

TFII has not had an independent security audit. Run it behind TLS, keep it patched, and treat it like any other
internet-facing service.
