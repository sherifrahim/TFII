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

Dependabot flags known-vulnerable packages. As of 2026-10-02 `npm audit` reports 0 findings for the frontend and the
backend has no known-vulnerable direct dependency.

**What ships.** The production image serves a static bundle (react, react-dom, the app's own code) from nginx. The
build tools (Vite, Vitest, ESLint) run only in the Docker build stage, on `npm start` and in the tests; none of them is
in the image that serves users.

**What changed.** The frontend used Create React App (`react-scripts` 5.0.1, unmaintained), which pinned old versions of
`webpack-dev-server`, `postcss`, `svgo`, `nth-check`, `jest` and others. Those alerts could not be fixed by upgrading, so
the build moved to Vite. The backend used `python-jose`, which depends on `ecdsa` (a timing side channel with no fix,
[CVE-2024-23342](https://github.com/advisories/GHSA-wj6h-64fc-37mp)); session tokens are now signed and verified with
PyJWT, which does not use `ecdsa`. Tokens stay HS256 and existing sessions keep working.

Run `npm audit` in `frontend/` and `pip-audit -r backend/requirements.txt` to check the current state yourself; new
advisories appear over time.

TFII has not had an independent security audit. Run it behind TLS, keep it patched, and treat it like any other
internet-facing service.
