FROM ubuntu:24.04

ARG PG_MAJOR=18
ENV DEBIAN_FRONTEND=noninteractive
ENV PG_MAJOR=${PG_MAJOR}
ENV PG_BINDIR=/usr/lib/postgresql/${PG_MAJOR}/bin
ENV PATH=${PG_BINDIR}:$PATH

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      gnupg \
      make \
      gcc \
      libc6-dev && \
    mkdir -p /usr/share/keyrings && \
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | \
      gpg --dearmor -o /usr/share/keyrings/postgresql.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/postgresql.gpg] https://apt.postgresql.org/pub/repos/apt noble-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      postgresql-${PG_MAJOR} \
      postgresql-contrib-${PG_MAJOR} \
      postgresql-server-dev-${PG_MAJOR} && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY docker/run-regression.sh /usr/local/bin/run-regression.sh
RUN chmod +x /usr/local/bin/run-regression.sh

CMD ["/usr/local/bin/run-regression.sh"]
