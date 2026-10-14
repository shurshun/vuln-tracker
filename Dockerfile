FROM ghcr.io/aquasecurity/trivy:0.75.0 AS trivy

FROM ghcr.io/astral-sh/uv:0.13.1-python3.13-trixie-slim AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM ghcr.io/astral-sh/uv:0.13.1-python3.13-trixie-slim
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /app/.venv /app/.venv

# The app runs from its venv. The image's own pip is unused and ships
# vendored packages with their own CVEs.
RUN python -m pip uninstall --yes --root-user-action=ignore pip
ENV PATH=/app/.venv/bin:$PATH
USER 65534:65534
ENTRYPOINT ["vuln-tracker"]
