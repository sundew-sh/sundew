FROM python:3.13-alpine AS builder

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install .


FROM python:3.13-alpine

RUN addgroup -g 65532 sundew && \
    adduser -u 65532 -G sundew -s /bin/false -D sundew

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
