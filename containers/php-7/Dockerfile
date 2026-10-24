# Branch-specific local PHP 7.x backports; no 115560 candidates.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf bison re2c pkg-config ca-certificates xz-utils patch \
    && rm -rf /var/lib/apt/lists/*
ARG BRANCH
ARG VERSION
ARG SHA256
WORKDIR /usr/src/php
COPY downloads/php-${VERSION}.tar.xz /tmp/php.tar.xz
RUN test -n "$SHA256" && echo "$SHA256  /tmp/php.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/php.tar.xz --strip-components=1 && rm /tmp/php.tar.xz
COPY php-${BRANCH}-patches/series /patches/series
COPY php-${BRANCH}-patches/CVE-2026-109619/002-restore-upload-progress.patch /patches/CVE-2026-109619/002-restore-upload-progress.patch
COPY php-${BRANCH}-patches/CVE-2026-109619/003-harden-progress-record.patch /patches/CVE-2026-109619/003-harden-progress-record.patch
COPY php-${BRANCH}-patches/CVE-2026-109618/001-avoid-state-corruption.patch /patches/CVE-2026-109618/001-avoid-state-corruption.patch
RUN set -eu; while IFS= read -r patchfile; do \
      case "$patchfile" in ''|'#'*) continue ;; esac; \
      patch --batch --fuzz=0 -p1 < "/patches/$patchfile"; \
    done < /patches/series
ARG JOBS=4
ARG DEBUG=0
# -fcommon supports legacy PHP globals with modern GCC (default changed in GCC 10).
RUN if [ "$DEBUG" = 1 ]; then debug_flag=--enable-debug; else debug_flag=; fi; \
    CFLAGS='-O2 -g -fcommon' ./configure --disable-all --enable-cli --enable-fpm \
      --enable-session --enable-opcache --enable-json $debug_flag \
    && make -j"$JOBS"
CMD ["sapi/cli/php", "-v"]
