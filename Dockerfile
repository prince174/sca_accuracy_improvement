FROM anchore/syft:v1.51.1@sha256:95fe0835e5bebc6f8b1f8acef68d47d63d594ef4c0f25c097ff853b23cbac74c AS syft
FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

RUN apt-get update \
    && apt-get install --yes --no-install-recommends docker.io \
    && rm -rf /var/lib/apt/lists/*

COPY --from=syft /syft /usr/local/bin/syft

WORKDIR /opt/sca-accuracy
COPY . .
RUN pip install --no-cache-dir ".[service]"

ENV SCA_WORKSPACE=/workspace
EXPOSE 8080
VOLUME ["/workspace"]
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"

CMD ["sca-accuracy-service"]
