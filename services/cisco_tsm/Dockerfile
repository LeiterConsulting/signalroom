FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/models/huggingface \
    MPLCONFIGDIR=/tmp/matplotlib \
    XDG_CACHE_HOME=/tmp/cache

WORKDIR /service
RUN useradd --create-home --uid 10001 modelrunner \
    && mkdir -p /models/huggingface \
    && chown -R modelrunner:modelrunner /models /service
COPY app.py /service/app.py
RUN pip install --no-cache-dir \
    cisco-tsm==1.0.2 \
    fastapi==0.116.1 \
    "huggingface-hub>=0.27,<2" \
    "uvicorn[standard]==0.35.0"

USER modelrunner
EXPOSE 8080
HEALTHCHECK --interval=20s --timeout=5s --start-period=30s --retries=30 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
