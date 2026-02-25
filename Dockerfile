FROM dhi.io/python:3.13-dev AS builder

WORKDIR /app

RUN python -m venv /app/venv

COPY pyproject.toml README.md ./
COPY src/ src/

RUN /app/venv/bin/pip install --no-cache-dir . && \
    mkdir -p /app/data && chown 65532:65532 /app/data


FROM dhi.io/python:3.13

WORKDIR /app

ENV PATH="/app/venv/bin:$PATH"

COPY --from=builder /app/venv /app/venv
COPY --from=builder --chown=65532:65532 /app/data /app/data
COPY sundew.yaml /app/sundew.yaml

EXPOSE 8080

VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

ENTRYPOINT ["sundew"]
CMD ["serve"]
