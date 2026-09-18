# sluice runtime image. Built with uv for reproducible installs.
FROM python:3.12-slim AS base

# uv: fast, lockfile-based installs.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Install dependencies first (cached until the lockfile changes).
COPY pyproject.toml uv.lock README.md ./
COPY sluice ./sluice
RUN uv sync --frozen --extra openai --extra anthropic --no-dev

# Copy the rest (examples, deploy scripts).
COPY examples ./examples
COPY deploy ./deploy

ENV PATH="/app/.venv/bin:${PATH}"
ENTRYPOINT ["sluice"]
CMD ["--help"]
