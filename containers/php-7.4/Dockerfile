FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf bison re2c pkg-config ca-certificates xz-utils patch \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/php
COPY downloads/php-7.4.33.tar.xz /tmp/php.tar.xz
RUN echo '924846abf93bc613815c55dd3f5809377813ac62a9ec4eb3778675b82a27b927  /tmp/php.tar.xz' | sha256sum -c - \
    && tar -xJf /tmp/php.tar.xz --strip-components=1 && rm /tmp/php.tar.xz
COPY php-7.4-patches/series /patches/series
COPY php-7.4-patches/CVE-2026-109619/002-restore-upload-progress.patch /patches/CVE-2026-109619/002-restore-upload-progress.patch
COPY php-7.4-patches/CVE-2026-109619/003-harden-progress-record.patch /patches/CVE-2026-109619/003-harden-progress-record.patch
COPY php-7.4-patches/CVE-2026-109618/001-avoid-state-corruption.patch /patches/CVE-2026-109618/001-avoid-state-corruption.patch
RUN set -eu; while IFS= read -r patchfile; do \
      case "$patchfile" in ''|'#'*) continue ;; esac; \
      patch --batch --fuzz=0 -p1 < "/patches/$patchfile"; \
    done < /patches/series
ARG JOBS=4
RUN ./configure --disable-all --enable-cli --enable-fpm --enable-session --enable-opcache --enable-json \
    && make -j"$JOBS"
# Development test image; includes the upstream upload-progress disablement.
CMD ["sapi/cli/php", "-v"]
