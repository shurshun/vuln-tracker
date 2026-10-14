FROM public.ecr.aws/aquasecurity/trivy:0.74.0 AS trivy

FROM ghcr.io/astral-sh/uv:0.12.10 AS uv

FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH
USER 65534:65534
ENTRYPOINT ["vuln-tracker"]
