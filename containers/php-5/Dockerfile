FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf bison re2c pkg-config ca-certificates gzip patch \
    && rm -rf /var/lib/apt/lists/*
ARG BRANCH
ARG VERSION
ARG SHA256
WORKDIR /usr/src/php
COPY php-${BRANCH}-patches/ /patches/
COPY downloads/php-${VERSION}.tar.gz /tmp/php.tar.gz
RUN echo "${SHA256}  /tmp/php.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/php.tar.gz --strip-components=1 && rm /tmp/php.tar.gz
RUN set -eu; while IFS= read -r patchfile; do \
      case "$patchfile" in ''|'#'*) continue ;; esac; \
      patch --batch --fuzz=0 -p1 < "/patches/$patchfile"; \
    done < /patches/series
ARG JOBS=3
ARG DEBUG=0
# Keep shipped parser sources: the releases predate current bison/re2c.
# PHP 5.4 predates bundled OPcache. -fcommon supports these old sources on GCC 10+.
RUN set -eu; debug_flag=; opcache_flag=; \
    if [ "$DEBUG" = 1 ]; then debug_flag=--enable-debug; fi; \
    if [ "$BRANCH" != 5.4 ]; then opcache_flag=--enable-opcache; fi; \
    CFLAGS='-O2 -g -fcommon' ./configure --disable-all --enable-cli --enable-fpm \
      --enable-session --enable-json $opcache_flag $debug_flag \
    && make -j"$JOBS"
CMD ["sapi/cli/php", "-v"]
