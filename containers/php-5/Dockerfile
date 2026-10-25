FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf bison re2c pkg-config ca-certificates gzip patch \
    && rm -rf /var/lib/apt/lists/*
ARG BRANCH
ARG VERSION
ARG SHA256
ARG VARIANT=full
ARG SKIP_PATCHES=""
WORKDIR /usr/src/php
COPY php-${BRANCH}-patches/ /patches/
COPY downloads/php-${VERSION}.tar.gz /tmp/php.tar.gz
RUN echo "${SHA256}  /tmp/php.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/php.tar.gz --strip-components=1 && rm /tmp/php.tar.gz
# SKIP_PATCHES is a comma-separated list of series entries to omit, used to build
# single-patch-reverted variants for evidence attribution. Every applied and
# skipped patch is recorded with its SHA-256 in the image manifest.
RUN set -eu; applied=''; skipped=''; \
    while IFS= read -r patchfile; do \
      case "$patchfile" in ''|'#'*) continue ;; esac; \
      sum=$(sha256sum "/patches/$patchfile" | cut -d' ' -f1); \
      case ",${SKIP_PATCHES}," in \
        *",$patchfile,"*) skipped="$skipped{\"path\":\"$patchfile\",\"sha256\":\"$sum\"}," ;; \
        *) patch --batch --fuzz=0 -p1 < "/patches/$patchfile"; \
           applied="$applied{\"path\":\"$patchfile\",\"sha256\":\"$sum\"}," ;; \
      esac; \
    done < /patches/series; \
    mkdir -p /usr/local/share; \
    printf '{"branch":"%s","version":"%s","variant":"%s","source_sha256":"%s","applied":[%s],"skipped":[%s],"configure":"--disable-all --enable-cli --enable-fpm --enable-session --enable-json","sapi":"cli,fpm"}\n' \
      "$BRANCH" "$VERSION" "$VARIANT" "$SHA256" \
      "${applied%,}" "${skipped%,}" > /usr/local/share/es-php-variant.json; \
    cat /usr/local/share/es-php-variant.json
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
LABEL org.centillex.es-php.variant="$VARIANT"
CMD ["sapi/cli/php", "-v"]
