FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install --yes --no-install-recommends docker.io \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sca-accuracy
COPY . .
RUN pip install --no-cache-dir ".[service]"

ENV SCA_WORKSPACE=/workspace
EXPOSE 8080
VOLUME ["/workspace"]

CMD ["sca-accuracy-service"]
