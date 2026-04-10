FROM python:3.11-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    APKTOOL_VERSION=2.10.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        adb \
        sqlite3 \
        binutils \
        openjdk-17-jre-headless \
        wget \
        ca-certificates \
        tar \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" \
        -O /usr/local/bin/apktool \
    && wget -q "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar" \
        -O /usr/local/bin/apktool.jar \
    && chmod +x /usr/local/bin/apktool

RUN pip install --no-cache-dir drozer

# Install Presidio (regex + checksum validators, no ML)
RUN pip install --no-cache-dir presidio-analyzer>=2.2.35

# Optional: install GLiNER NER backend for ML-based PII detection
ARG ENABLE_NER=false
RUN if [ "$ENABLE_NER" = "true" ]; then \
        pip install --no-cache-dir "presidio-analyzer[gliner]>=2.2.35"; \
    fi

# Pre-download GLiNER model if NER is enabled (~560 MB)
RUN if [ "$ENABLE_NER" = "true" ]; then \
        python3 -c "from gliner import GLiNER; GLiNER.from_pretrained('urchade/gliner_multi_pii-v1')"; \
    fi

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/output

# Usage:
#   docker build -t trashdroid .
#   docker build --build-arg ENABLE_NER=true -t trashdroid:ner .
#   docker run -v gliner_cache:/root/.cache/huggingface trashdroid --ner

ENTRYPOINT ["python", "main.py"]
