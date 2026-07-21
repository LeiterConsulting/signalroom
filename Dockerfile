FROM python:3.12-slim

WORKDIR /app
ENV SIGNALROOM_ROOT=/app \
    SIGNALROOM_DATA_DIR=/app/data \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
RUN mkdir -p /app/data
EXPOSE 8003
CMD ["uvicorn", "splunk_security_agent.app:app", "--host", "0.0.0.0", "--port", "8003"]
