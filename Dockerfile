# syntax=docker/dockerfile:1
FROM python:3.13-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
# uv for fast, reproducible installs
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv
COPY pyproject.toml README.md ./
COPY src ./src
RUN uv pip install --system --no-cache ".[redis,postgres]"
RUN rm -f /usr/local/bin/uv

FROM python:3.13-slim AS runtime
ENV PYTHONUNBUFFERED=1
# xmlsec1 binary (pysaml2 shells out to it); libxml2 runtime deps come with it
RUN apt-get update \
 && apt-get install -y --no-install-recommends xmlsec1 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
WORKDIR /app
# Smoke check baked in: import + xmlsec1 present
RUN python -c "import fastapi_auth.saml; import shutil; assert shutil.which('xmlsec1'), 'xmlsec1 missing'"
CMD ["python", "-c", "import fastapi_auth.saml as s; print('fastapi-auth-saml-federated', s.__version__)"]
