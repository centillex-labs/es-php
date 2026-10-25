# php-cgi + Apache CGI build for the Chain C (.user.ini handler mismatch) harness.
#
# Chain C needs per-directory .user.ini support, which only the CGI/FastCGI
# SAPIs provide -- mod_php uses .htaccess, and the CLI server ignores both.
# That is why this chain was previously recorded as "not runnable".
#
# Development/test image only. Never expose it.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf bison re2c pkg-config ca-certificates gzip patch \
    apache2 \
    && rm -rf /var/lib/apt/lists/*

ARG BRANCH
ARG VERSION
ARG SHA256
WORKDIR /usr/src/php
COPY downloads/php-${VERSION}.tar.gz /tmp/php.tar.gz
RUN echo "${SHA256}  /tmp/php.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/php.tar.gz --strip-components=1 && rm /tmp/php.tar.gz

COPY php-${BRANCH}-patches/series /patches/series
COPY php-${BRANCH}-patches/CVE-2026-109619/002-restore-upload-progress.patch /patches/CVE-2026-109619/002-restore-upload-progress.patch
COPY php-${BRANCH}-patches/CVE-2026-109619/003-harden-progress-record.patch /patches/CVE-2026-109619/003-harden-progress-record.patch
COPY php-${BRANCH}-patches/CVE-2026-109618/001-avoid-state-corruption.patch /patches/CVE-2026-109618/001-avoid-state-corruption.patch
COPY php-${BRANCH}-patches/CVE-2019-11043/001-bound-path-info.patch /patches/CVE-2019-11043/001-bound-path-info.patch

# SKIP_PATCHES=1 builds the unpatched baseline for A/B comparison.
ARG SKIP_PATCHES=0
RUN set -eu; \
    if [ "$SKIP_PATCHES" = "1" ]; then echo 'baseline: patch series skipped'; exit 0; fi; \
    while IFS= read -r patchfile; do \
      case "$patchfile" in ''|'#'*) continue ;; esac; \
      patch --batch --fuzz=0 -p1 < "/patches/$patchfile"; \
    done < /patches/series

ARG JOBS=3
RUN CFLAGS='-O2 -g -fcommon' ./configure --disable-all --enable-cgi \
      --enable-session --enable-json \
    && make -j"$JOBS"

RUN set -eu; \
    a2dismod mpm_event mpm_worker || true; \
    a2enmod mpm_prefork cgid actions alias; \
    printf 'Listen 8080\nServerName localhost\nDocumentRoot /web\n' \
      > /etc/apache2/conf-available/lab.conf; \
    printf '<Directory /web>\n  Options +ExecCGI\n  AllowOverride All\n  Require all granted\n</Directory>\n' \
      >> /etc/apache2/conf-available/lab.conf; \
    printf 'Action application/x-httpd-php /cgi-bin/php-cgi\nAddHandler application/x-httpd-php .php\n' \
      >> /etc/apache2/conf-available/lab.conf; \
    a2enconf lab; \
    rm -f /etc/apache2/sites-enabled/*

ENV APACHE_RUN_USER=www-data \
    APACHE_RUN_GROUP=www-data \
    APACHE_LOG_DIR=/var/log/apache2 \
    APACHE_PID_FILE=/var/run/apache2/apache2.pid \
    APACHE_RUN_DIR=/var/run/apache2 \
    APACHE_LOCK_DIR=/var/lock/apache2 \
    PHP_MEMORY_LIMIT=32M

# php.ini is written at start-up. PHP 5.4 reads /usr/local/lib/php.ini.
# cgi.force_redirect=0 keeps php-cgi usable behind Apache's Action directive.
CMD ["/bin/sh", "-ec", "mkdir -p /var/run/apache2 /var/lock/apache2 /usr/lib/cgi-bin /data/sessions; chmod 1777 /data/sessions; cp sapi/cgi/php-cgi /usr/lib/cgi-bin/php-cgi; { echo 'error_reporting = E_ALL'; echo 'display_errors = On'; echo 'log_errors = On'; echo \"memory_limit = ${PHP_MEMORY_LIMIT}\"; echo 'cgi.force_redirect = 0'; echo 'session.save_path = /data/sessions'; echo 'session.use_cookies = 1'; echo 'session.use_only_cookies = 0'; echo 'session.use_strict_mode = 0'; echo 'session.upload_progress.enabled = 1'; echo 'session.upload_progress.cleanup = 0'; echo 'session.upload_progress.min_freq = 0'; echo 'upload_max_filesize = 1M'; echo 'post_max_size = 8M'; } > /usr/local/lib/php.ini; exec apachectl -DFOREGROUND"]
