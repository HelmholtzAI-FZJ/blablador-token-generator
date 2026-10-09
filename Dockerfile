FROM python:3.12-slim

WORKDIR /app

RUN pip install uv

COPY pyproject.toml ./
RUN uv pip install --system -e .

COPY . .

RUN useradd --system --uid 10001 --no-create-home app \
    && mkdir -p /app/data \
    && chown app /app/data

USER 10001

EXPOSE 8080

# Trust X-Forwarded-For only from the ingress so per-IP rate limits see
# the real client. Set FORWARDED_ALLOW_IPS to the ingress pod CIDR.
ENV FORWARDED_ALLOW_IPS=127.0.0.1

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers 2 --proxy-headers --forwarded-allow-ips \"$FORWARDED_ALLOW_IPS\""]