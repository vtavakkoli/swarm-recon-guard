FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Immutable image-build declaration checked against the run-time experiment SHA.
ARG SWARM_BUILD_COMMIT="not supplied"
ENV SWARM_IMAGE_COMMIT="${SWARM_BUILD_COMMIT}"

RUN addgroup --system app && adduser --system --ingroup app app

COPY pyproject.toml README.md LICENSE /app/
COPY src /app/src
RUN pip install --upgrade pip && pip install .

COPY scenarios /app/scenarios
COPY docs /app/docs

RUN mkdir -p /app/results && chown -R app:app /app
USER app

ENTRYPOINT ["python", "-m", "swarmguard.cli"]
