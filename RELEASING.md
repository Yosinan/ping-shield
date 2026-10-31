# Releasing ping-shield

Maintainer checklist. Publishing to PyPI requires the maintainer's project-scoped API token.

## Versioning

[Semantic Versioning](https://semver.org/). The only place the version is set is `__version__` in
`ping_shield/__init__.py`.

| Bump | When |
|---|---|
| MAJOR `2.0.0` | Something existing users rely on breaks: a CLI flag is removed or renamed, a config field changes meaning, or the state file needs a migration |
| MINOR `1.3.0` | New backwards-compatible features |
| PATCH `1.2.1` | Bug fixes only |

A version that's already on PyPI can't be uploaded again, and a pushed tag shouldn't be moved. If
something is wrong after a release, fix it in a patch release.

## Steps

1. **Changelog:** in `CHANGELOG.md`, rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`, add a new empty
   `[Unreleased]` section, and update the compare links at the bottom.
2. **Version:** set `__version__ = "X.Y.Z"` in `ping_shield/__init__.py`.
3. **Commit, tag and push:**
   ```bash
   git commit -am "Release X.Y.Z"
   git tag -a vX.Y.Z -m "ping-shield X.Y.Z"
   git push origin main vX.Y.Z
   ```
4. **Build from the tag and upload.** When twine asks, the username is `__token__` and the password is
   your PyPI token:
   ```bash
   git checkout vX.Y.Z
   rm -rf dist/ && python3 -m build
   python3 -m twine check --strict dist/*
   python3 -m twine upload dist/*
   git checkout main
   ```
5. **Check the upload:**
   ```bash
   python3 -m venv /tmp/ps-try && /tmp/ps-try/bin/pip install ping-shield==X.Y.Z
   /tmp/ps-try/bin/ping-shield --version
   ```
6. **GitHub release:** use the changelog section as the release notes:
   ```bash
   gh release create vX.Y.Z dist/* --title "ping-shield X.Y.Z" \
     --notes-file <(sed -n '/^## \[X.Y.Z\]/,/^## \[/p' CHANGELOG.md | sed '1d;$d')
   ```
