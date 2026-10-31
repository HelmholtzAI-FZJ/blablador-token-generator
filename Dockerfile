# Base images are pinned by digest; Dependabot proposes updates (it reads
# only FROM lines, hence the stage for uv).
FROM ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0 AS uv

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS build

COPY --from=uv /uv /bin/uv

# Install exactly the locked, hash-verified dependency set into a venv.
# uv and its cache stay in this stage; only the venv reaches the image.
COPY pyproject.toml uv.lock /build/
RUN uv export --frozen --no-dev --no-emit-project --project /build -o /build/requirements.txt \
    && uv venv /opt/venv \
    && VIRTUAL_ENV=/opt/venv uv pip install --no-cache --require-hashes -r /build/requirements.txt \
    && rm -f /opt/venv/.lock


FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Blablador Token Generator" \
      org.opencontainers.image.description="API token service for Blablador, with Helmholtz/JSC OAuth sign-in" \
      org.opencontainers.image.source="https://github.com/HelmholtzAI-FZJ/blablador-token-generator" \
      org.opencontainers.image.documentation="https://helmholtzai-fzj.github.io/blablador-token-generator/" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    APP_ENVIRONMENT=production \
    CONFIG_PATH=/app/config/config.yaml \
    WORKERS=2

WORKDIR /app

COPY app/ ./app/

RUN /usr/local/bin/python -c 'import pathlib, shutil, sysconfig; site = pathlib.Path(sysconfig.get_paths()["purelib"]); targets = list(site.glob("pip*")) + [pathlib.Path(sysconfig.get_paths()["stdlib"]) / "ensurepip"] + list(pathlib.Path("/usr/local/bin").glob("pip*")); [(shutil.rmtree(p) if p.is_dir() else p.unlink()) for p in targets if p.exists()]' \
    && apt-get update \
    && apt-get install --no-install-recommends -y --only-upgrade liblzma5 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home app \
    && mkdir -p /app/data \
    && chown app /app/data \
    && find / -xdev -perm /6000 -type f -exec chmod a-s {} +

USER 10001

EXPOSE 8080

# Trust only the actual ingress source addresses, with network isolation.
ENV FORWARDED_ALLOW_IPS=127.0.0.1

CMD ["sh", "/app/app/entrypoint.sh"]
