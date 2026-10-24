FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf bison re2c pkg-config ca-certificates xz-utils patch \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/php
COPY downloads/php-8.1.34.tar.xz /tmp/php.tar.xz
RUN echo 'ffa9e0982e82eeaea848f57687b425ed173aa278fe563001310ae2638db5c251  /tmp/php.tar.xz' | sha256sum -c - \
    && tar -xJf /tmp/php.tar.xz --strip-components=1 && rm /tmp/php.tar.xz
# Copy only the active stack. Candidate patches are not shipped in this image.
COPY php-8.1-patches/series /patches/series
COPY php-8.1-patches/CVE-2026-109619/002-restore-upload-progress.patch /patches/CVE-2026-109619/002-restore-upload-progress.patch
COPY php-8.1-patches/CVE-2026-109619/003-harden-progress-record.patch /patches/CVE-2026-109619/003-harden-progress-record.patch
COPY php-8.1-patches/CVE-2026-109618/001-avoid-state-corruption.patch /patches/CVE-2026-109618/001-avoid-state-corruption.patch
RUN set -eu; while IFS= read -r patchfile; do \
      case "$patchfile" in ''|'#'*) continue ;; esac; \
      patch --batch --fuzz=0 -p1 < "/patches/$patchfile"; \
    done < /patches/series

ARG JOBS=4
RUN ./configure --disable-all --enable-cli --enable-fpm --enable-session \
      --enable-opcache --enable-zend-test \
    && make -j"$JOBS"

# Development/test image, not a production runtime. No service is started.
CMD ["sapi/cli/php", "-v"]
