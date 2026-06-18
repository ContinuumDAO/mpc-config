# Build from mpc-config repo root:
#   docker build -f docker-extension/Dockerfile -t continuumdao/continuum-node-installer:0.1.16 .
#
# Install extension (Windows / macOS Docker Desktop):
#   docker extension install continuumdao/continuum-node-installer:0.1.16
#
# Windows: install orchestration runs via host WSL → ~/mpc-config (no baked /mpc-config in this image).
#
# syntax=docker/dockerfile:1

FROM node:20-bookworm-slim AS ui-build
WORKDIR /ui
COPY docker-extension/ui/package.json ./
RUN npm install
COPY docker-extension/ui/ ./
RUN npm run build

FROM debian:bookworm-slim

# Required Docker Desktop Extension labels (see docker-extension/README.md).
LABEL org.opencontainers.image.title="Continuum Node" \
    org.opencontainers.image.description="Install a local Continuum MPC node on Docker Desktop." \
    org.opencontainers.image.vendor="ContinuumDAO" \
    com.docker.desktop.extension.api.version=">= 0.3.3" \
    com.docker.desktop.extension.icon="continuum-icon.svg" \
    com.docker.extension.screenshots="[]" \
    com.docker.extension.detailed-description="Provision certificates, configs.yaml, and start the Continuum MPC stack via Docker Desktop. Windows: clones mpc-config to WSL ~/mpc-config and runs docker compose from there." \
    com.docker.extension.publisher-url="https://continuumdao.org" \
    com.docker.extension.changelog="0.1.16: fix install progress spinner (persistent DOM, full 360° rotation)."

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ui-build /ui/dist /ui
COPY docker-extension/metadata.json /metadata.json
COPY docker-extension/docker-compose.yaml /docker-compose.yaml
COPY docker-extension/continuum-icon.svg /continuum-icon.svg
COPY docker-extension/host/windows/continuum-wsl.cmd /host/windows/continuum-wsl.cmd
COPY docker-extension/host/windows/continuum-register-watcher.cmd /host/windows/continuum-register-watcher.cmd
COPY docker-extension/host/linux/continuum-linux.sh /host/linux/continuum-linux.sh
COPY docker-extension/host/linux/continuum-orchestrate.sh /host/linux/continuum-orchestrate.sh
RUN chmod +x /host/linux/continuum-linux.sh /host/linux/continuum-orchestrate.sh
COPY docker-extension/vm/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /
ENTRYPOINT ["/entrypoint.sh"]
