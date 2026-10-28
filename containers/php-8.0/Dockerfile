FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf bison re2c pkg-config ca-certificates xz-utils patch \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/php
COPY downloads/php-8.0.30.tar.xz /tmp/php.tar.xz
RUN echo '216ab305737a5d392107112d618a755dc5df42058226f1670e9db90e77d777d9  /tmp/php.tar.xz' | sha256sum -c - \
    && tar -xJf /tmp/php.tar.xz --strip-components=1 && rm /tmp/php.tar.xz
# Copy only the active stack. Candidate patches are not shipped in this image.
COPY php-8.0-patches/series /patches/series
COPY php-8.0-patches/CVE-2026-109619/002-restore-upload-progress.patch /patches/CVE-2026-109619/002-restore-upload-progress.patch
COPY php-8.0-patches/CVE-2026-109619/003-harden-progress-record.patch /patches/CVE-2026-109619/003-harden-progress-record.patch
COPY php-8.0-patches/CVE-2026-109618/001-avoid-state-corruption.patch /patches/CVE-2026-109618/001-avoid-state-corruption.patch
# SKIP_PATCHES=1 builds the unpatched control for A/B regression tests.
ARG SKIP_PATCHES=0
RUN set -eu; [ "$SKIP_PATCHES" = "1" ] && { echo 'baseline: patch series skipped'; exit 0; }; \
    while IFS= read -r patchfile; do \
      case "$patchfile" in ''|'#'*) continue ;; esac; \
      patch --batch --fuzz=0 -p1 < "/patches/$patchfile"; \
    done < /patches/series

ARG JOBS=4
RUN ./configure --disable-all --enable-cli --enable-fpm --enable-session \
      --enable-opcache --enable-zend-test \
    && make -j"$JOBS"

# Development/test image, not a production runtime. No service is started.
CMD ["sapi/cli/php", "-v"]
