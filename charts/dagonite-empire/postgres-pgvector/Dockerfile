# Bitnami PostgreSQL with pgvector extension layered on top.
# Keeps the bitnami entrypoint, init scripts, paths and uid 1001 intact so the
# upstream bitnami/postgresql Helm chart works without further changes.
#
# Build:
#   docker build --build-arg BITNAMI_TAG=16 \
#     -t ghcr.io/<owner>/postgresql-pgvector:16 \
#     charts/dagonite-empire/postgres-pgvector
ARG BITNAMI_TAG=16

FROM bitnamilegacy/postgresql:${BITNAMI_TAG} AS builder
USER root
RUN install_packages git build-essential ca-certificates
ARG PGVECTOR_VERSION=v0.8.0
WORKDIR /tmp/pgvector
# OPTFLAGS="" disables pgvector's default `-march=native`, which would otherwise
# bake in the build host's CPU features (e.g. AVX-512 on GitHub runners) and
# cause `SIGILL: Illegal instruction` on older target CPUs.
RUN git clone --branch ${PGVECTOR_VERSION} --depth 1 https://github.com/pgvector/pgvector.git . \
 && make OPTFLAGS="" PG_CONFIG=/opt/bitnami/postgresql/bin/pg_config \
 && make OPTFLAGS="" install PG_CONFIG=/opt/bitnami/postgresql/bin/pg_config

FROM bitnamilegacy/postgresql:${BITNAMI_TAG}
COPY --from=builder /opt/bitnami/postgresql/lib/vector.so \
                    /opt/bitnami/postgresql/lib/
COPY --from=builder /opt/bitnami/postgresql/share/extension/vector* \
                    /opt/bitnami/postgresql/share/extension/
USER 1001
