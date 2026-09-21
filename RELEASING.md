# Releasing jev-guard

Publishing is automated via **PyPI Trusted Publishing** — no API token is ever
stored in the repo or entered by hand. GitHub authenticates to PyPI over OIDC.

## One-time setup (maintainer, ~2 min)

1. Create the project on PyPI (or reserve the name) at https://pypi.org.
2. On PyPI → the `jev-guard` project → **Publishing** → add a trusted publisher:
   - Owner: `ppradyoth`
   - Repository: `jev-guard`
   - Workflow: `release.yml`
   - Environment: `pypi`
3. In the GitHub repo → Settings → Environments → create an environment named
   `pypi` (optionally add a required reviewer for a manual gate).

## Cutting a release

1. Bump the version in `pyproject.toml` and `src/jev_guard/__init__.py`, and add
   a `CHANGELOG.md` entry. Commit.
2. Tag and push: `git tag -a vX.Y.Z -m vX.Y.Z && git push origin main --tags`.
3. Create the GitHub Release for that tag (`gh release create vX.Y.Z --latest ...`).
   Publishing the release triggers `release.yml`, which builds, `twine check`s,
   and uploads to PyPI.
4. Verify: `pipx run jev-guard==X.Y.Z --version`.

## Local build (for inspection only)

```bash
uv build && uvx twine check dist/*
```
