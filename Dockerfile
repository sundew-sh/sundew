FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install .


FROM python:3.12-slim

RUN groupadd --gid 1001 sundew && \
    useradd --uid 1001 --gid sundew --shell /bin/false sundew

COPY --from=builder /install /usr/local

COPY sundew.yaml /app/sundew.yaml

WORKDIR /app

RUN mkdir -p /app/data && chown sundew:sundew /app/data

USER sundew

EXPOSE 8080

VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

ENTRYPOINT ["sundew"]
CMD ["serve"]
