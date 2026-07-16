FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
COPY data ./data
EXPOSE 8003
CMD ["uvicorn", "splunk_security_agent.app:app", "--host", "0.0.0.0", "--port", "8003"]

