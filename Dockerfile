FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOGSERVER_DB=/data/logs.db

WORKDIR /app
COPY . /app
RUN groupadd --gid 10001 logserver \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /app --shell /usr/sbin/nologin logserver \
    && mkdir -p /data \
    && chown logserver:logserver /data

USER logserver
EXPOSE 8080/tcp 5514/udp
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=2)"]
CMD ["python", "-m", "logserver"]
