FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY ccdc_scorer ./ccdc_scorer
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 scorer

USER scorer
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["eku-ccdc-scorer"]
CMD ["--config", "/data/config.json", "--outdir", "/data/out", "--host", "0.0.0.0", "--port", "8080"]
