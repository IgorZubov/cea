# CEA sandbox image: a tiny toolbox (node + npm, python3 + pip, git, curl, strace).
# Nothing from the checked target is ever baked into this image; the analysis
# scripts (agent.py / sinkhole.py) are mounted read-only at run time.
#
# Override bases if Docker Hub is rate-limited, e.g.
#   cea build --build-arg NODE_IMAGE=mirror.gcr.io/library/node:22-bookworm-slim \
#             --build-arg BASE_IMAGE=mirror.gcr.io/library/ubuntu:24.04
ARG NODE_IMAGE=node:22-bookworm-slim
ARG BASE_IMAGE=ubuntu:24.04

FROM ${NODE_IMAGE} AS node

FROM ${BASE_IMAGE}
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-pip python3-setuptools python3-wheel python3-venv \
      strace git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && mkdir -p /sandbox /work /out /home/dev /cea \
 && chmod 1777 /sandbox /out /home/dev
LABEL org.cea.sandbox="1"
