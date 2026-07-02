FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    openssh-client \
    python3 \
    python3-pip \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

COPY worker/install-scan-tools.sh /tmp/install-scan-tools.sh
RUN sed -i 's/\r$//' /tmp/install-scan-tools.sh \
    && chmod +x /tmp/install-scan-tools.sh \
    && /tmp/install-scan-tools.sh

COPY backend/app /app/app

RUN mkdir -p /data/reports /usr/share/stigs

CMD ["celery", "-A", "app.tasks.celery_app", "worker", "--loglevel=info", "--concurrency=1"]
