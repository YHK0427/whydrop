# python:3.12-slim (Debian trixie), pinned by digest; iw pinned to the trixie version the Wi-Fi parser is tested against
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ARG IW_VERSION=6.9-1
RUN apt-get update \
 && apt-get install -y --no-install-recommends "iw=${IW_VERSION}" iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin whydrop \
 && mkdir -p /data && chown 10001:10001 /data

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /root/.cache

USER 10001
ENV WHYDROP_DB_PATH=/data/whydrop.db PYTHONUNBUFFERED=1
VOLUME /data
ENTRYPOINT ["whydrop"]
CMD ["agent"]
