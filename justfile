# sluice task runner (https://github.com/casey/just). `just` lists recipes.

default:
    @just --list

# --- Python ---
sync:
    uv sync --all-extras

fmt:
    uv run ruff format .
    uv run ruff check --fix .

lint:
    uv run ruff check .
    uv run ruff format --check .

types:
    uv run mypy

test *ARGS:
    uv run pytest {{ARGS}}

cov:
    uv run pytest --cov=sluice --cov-report=term-missing

# All Python gates, as CI runs them.
check: lint types
    uv run pytest --cov=sluice --cov-report=term

demo:
    uv run sluice run examples/inbox-assistant

demo-strict:
    uv run sluice run examples/inbox-assistant --mode strict --no-vanilla

trifecta:
    uv run sluice trifecta examples/inbox-assistant

bench *ARGS:
    uv run sluice bench {{ARGS}}

# --- TypeScript SDK ---
ts-install:
    cd sdk/typescript && npm install

ts-check:
    cd sdk/typescript && npm run typecheck && npm test && npm run build

# --- everything ---
all: check ts-check
