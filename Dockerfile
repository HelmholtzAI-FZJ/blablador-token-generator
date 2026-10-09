# Base image and uv are pinned by digest; Dependabot proposes updates.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS build

COPY --from=ghcr.io/astral-sh/uv:0.11.21@sha256:ff07b86af50d4d9391d9daf4ff89ce427bc544f9aae87057e69a1cc0aa369946 /uv /bin/uv

# Install exactly the locked, hash-verified dependency set into a venv.
# uv and its cache stay in this stage; only the venv reaches the image.
COPY pyproject.toml uv.lock /build/
RUN uv export --frozen --no-dev --no-emit-project --project /build -o /build/requirements.txt \
    && uv venv /opt/venv \
    && VIRTUAL_ENV=/opt/venv uv pip install --no-cache --require-hashes -r /build/requirements.txt


FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY app/ ./app/

RUN useradd --system --uid 10001 --no-create-home app \
    && mkdir -p /app/data \
    && chown app /app/data

USER 10001

EXPOSE 8080

# Trust X-Forwarded-For only from the ingress so per-IP rate limits see
# the real client. Set FORWARDED_ALLOW_IPS to the ingress pod CIDR.
ENV FORWARDED_ALLOW_IPS=127.0.0.1

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers 2 --proxy-headers --forwarded-allow-ips \"$FORWARDED_ALLOW_IPS\""]
