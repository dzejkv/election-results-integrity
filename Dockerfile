FROM python:3.13-slim

RUN useradd --create-home --uid 10001 eri
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY config/election.json ./config/election.json
RUN mkdir -p /app/data && chown eri /app/data

# The device registry is environment-specific: mount it read-only, e.g.
#   docker run -v $PWD/config/devices.json:/app/config/devices.json:ro -p 8000:8000 eri
USER eri
ENV ERI_DB=/app/data/eri.db \
    ERI_REGISTRY=/app/config/devices.json \
    ERI_ELECTION=/app/config/election.json

EXPOSE 8000
CMD ["uvicorn", "--factory", "eri.server:create_app", "--host", "0.0.0.0", "--port", "8000"]
