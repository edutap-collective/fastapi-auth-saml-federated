# Release to PyPI

Releases are published by `.github/workflows/release.yml` through
[PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/): GitHub
Actions proves its identity to PyPI with a short-lived OIDC token, so no API
token is stored anywhere.

## One-time setup

### PyPI: add a pending publisher

The project does not exist on PyPI before its first upload, so register a
*pending* publisher
([docs](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)):

1. Log in at <https://pypi.org> and open
   <https://pypi.org/manage/account/publishing/> (account **Publishing**).
2. Under **Add a new pending publisher**, choose **GitHub** and enter:

   | Field | Value |
   | ----- | ----- |
   | PyPI Project Name | `fastapi-auth-saml-federated` |
   | Owner | `edutap-collective` |
   | Repository name | `fastapi-auth-saml-federated` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` (optional on PyPI, but the workflow uses it) |

3. **Add**. The first successful upload turns it into a regular trusted
   publisher of the new project.

### GitHub: create the `pypi` environment

1. Repository **Settings → Environments → New environment**, name `pypi`,
   **Configure environment**.
2. Optional, recommended: **Required reviewers** -- add the maintainers who
   approve each upload. The publish job then waits for an approval.
3. **Deployment branches and tags** → **Selected branches and tags** →
   **Add deployment branch or tag rule**, ref type **Tag**, pattern `v*`, so
   only version tags can deploy to this environment.

## Releasing a version

1. Open a PR that sets `version` in `pyproject.toml` and `__version__` in
   `src/fastapi_auth/saml/__init__.py` (a test keeps both in step) and turns
   the `CHANGELOG.md` section into `## [X.Y.Z] - YYYY-MM-DD`.
2. Merge it to `main`.
3. Tag the merge commit on `main` and push the tag:

   ```bash
   git fetch origin
   git tag -a vX.Y.Z -m "vX.Y.Z" origin/main
   git push origin vX.Y.Z
   ```

4. The **Release** workflow aborts if the tag is not `v` + `project.version`
   or the tagged commit is not on `main`. Otherwise it builds sdist and wheel,
   checks their metadata, waits for an approval if the environment requires
   one, and uploads to PyPI.

A version can be uploaded to PyPI only once. If the workflow fails after the
upload, fix forward with a new patch version rather than re-tagging.
