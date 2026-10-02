# Contributing to TFII

Thanks for helping. Bug reports, feature ideas, docs fixes and pull requests are all welcome.

## Ways to help that are easy to start with

* Try the [Docker quick start](README.md#quick-start) on a clean machine and tell us where it was unclear.
* Report a wrong or confusing result (a verdict, a confidence score, a location) with the indicator that produced it.
* Pick an issue labelled `good first issue`, or something from [TODO.md](TODO.md).

## Development

```bash
# backend (creates and drops its own throwaway PostgreSQL database)
python3 -m venv venv && . venv/bin/activate
pip install -r backend/requirements-dev.txt
cd backend && python -m pytest

# frontend
cd frontend && npm ci
npm run lint && npm test
```

A local PostgreSQL is needed for the backend tests (`DB_HOST`, `DB_USER`, `DB_PASS`). The architecture, the data
model and the API are described in [docs/INTELLIGENCE_CORE.md](docs/INTELLIGENCE_CORE.md).

## Pull requests

* Keep a change focused, and add or update tests for behaviour you change. CI must pass (tests and lint).
* Schema changes are additive migrations in `backend/migrations.py`, never edits to old ones.
* Do not add anything that sends data to a new third-party service without saying so in the PR: TFII documents every
  outbound call in [docs/DATA_FLOWS.md](docs/DATA_FLOWS.md).
* Never commit secrets, API keys, real indicator data from a private feed, or `.env` files.

## Security issues

Please report them privately, as described in [SECURITY.md](SECURITY.md).
