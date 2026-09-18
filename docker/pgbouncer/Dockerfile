FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates curl libevent-dev libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl -fLsS https://github.com/pgbouncer/pgbouncer/releases/download/pgbouncer_1_25_2/pgbouncer-1.25.2.tar.gz -o pgbouncer.tar.gz \
    && echo '924ad35113fd0a71c8e2dbe85b5d03445532e2b7b37a9f8a48983beea238b332  pgbouncer.tar.gz' | sha256sum -c - \
    && tar xzf pgbouncer.tar.gz \
    && cd pgbouncer-1.25.2 && ./configure --prefix=/usr/local --without-cares --without-libidn --without-pam \
    && make -j2 pgbouncer && install -m 755 pgbouncer /usr/local/bin/pgbouncer
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
RUN apt-get update && apt-get install -y --no-install-recommends libevent-2.1-7 libssl3 ca-certificates && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 pooler && useradd -u 10001 -g pooler pooler
COPY --from=build /usr/local/bin/pgbouncer /usr/local/bin/pgbouncer
USER 10001:10001
ENTRYPOINT ["pgbouncer"]
CMD ["/etc/pgbouncer/pgbouncer.ini"]
