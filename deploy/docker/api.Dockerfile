# praxis-api: the Python package served by uvicorn. Build context: repo root.
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_NO_DEV=1
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-install-project
COPY src ./src
RUN uv sync --locked --no-editable
RUN useradd --system --uid 10001 praxis
USER praxis
ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8000
CMD ["sh", "-c", "praxis db-migrate && exec uvicorn praxis.api.app:app --host 0.0.0.0 --port 8000"]
