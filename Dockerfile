FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml requirements.txt ./
COPY scan4secrets ./scan4secrets
RUN pip install --no-cache-dir --upgrade pip build && \
    pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim
LABEL org.opencontainers.image.title="scan4secrets" \
      org.opencontainers.image.description="DAST + SAST secret scanner" \
      org.opencontainers.image.source="https://github.com/m14r41/scan4secrets"
RUN useradd -m -u 1000 scanner
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER scanner
WORKDIR /scan
ENTRYPOINT ["scan4secrets"]
CMD ["--help"]
