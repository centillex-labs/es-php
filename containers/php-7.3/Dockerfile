FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf bison re2c pkg-config ca-certificates xz-utils patch \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/php
COPY downloads/php-7.3.33.tar.xz /tmp/php.tar.xz
RUN echo '166eaccde933381da9516a2b70ad0f447d7cec4b603d07b9a916032b215b90cc  /tmp/php.tar.xz' | sha256sum -c - \
    && tar -xJf /tmp/php.tar.xz --strip-components=1 && rm /tmp/php.tar.xz
COPY php-7.3-patches/series /patches/series
COPY php-7.3-patches/CVE-2026-109619/002-restore-upload-progress.patch /patches/CVE-2026-109619/002-restore-upload-progress.patch
COPY php-7.3-patches/CVE-2026-109619/003-harden-progress-filename.patch /patches/CVE-2026-109619/003-harden-progress-filename.patch
COPY php-7.3-patches/CVE-2026-109618/001-avoid-state-corruption.patch /patches/CVE-2026-109618/001-avoid-state-corruption.patch
RUN set -eu; while IFS= read -r patchfile; do \
      case "$patchfile" in ''|'#'*) continue ;; esac; \
      patch --batch --fuzz=0 -p1 < "/patches/$patchfile"; \
    done < /patches/series
ARG JOBS=4
ARG DEBUG=0
RUN if [ "$DEBUG" = 1 ]; then debug_flag=--enable-debug; else debug_flag=; fi; \
    ./configure --disable-all --enable-cli --enable-fpm --enable-session --enable-opcache --enable-json $debug_flag \
    && make -j"$JOBS"
CMD ["sapi/cli/php", "-v"]
