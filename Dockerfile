# syntax=docker/dockerfile:1
FROM python:3.12-slim

LABEL maintainer="w01f"
LABEL description="Security log parsing toolkit for SOC analysts"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY uv.lock pyproject.toml ./

RUN pip install uv && \
    uv sync --frozen --no-dev

COPY . .

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]