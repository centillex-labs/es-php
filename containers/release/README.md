# Production runtime image plan

Status: **planned; not built or published yet**. This document records the agreed
LTS 1 production matrix. Existing Dockerfiles elsewhere under `containers/` are
test infrastructure, not the production images described here.

Product: **Extended Support PHP**

- Container package: `ghcr.io/centillex-labs/php`
- Source repository: https://github.com/centillex-labs/es-php
- Source release: https://github.com/centillex-labs/es-php/releases/tag/lts1
- Initial platform: `linux/amd64`
- Initial base: `debian:bookworm-slim`
- Build mode: non-debug, non-ZTS
- No bare `latest` tag.

## LTS 1 matrix

Each checkmark is a planned image configuration, not a completed build.

| PHP branch | Source version | CLI | FPM | Apache (mod_php) | Rollout stage |
| --- | --- | --- | --- | --- | --- |
| 5.4 | `5.4.45-lts1` | ✓ | ✓ | ✓ | Pilot |
| 5.5 | `5.5.38-lts1` | ✓ | ✓ | ✓ | Next |
| 5.6 | `5.6.40-lts1` | ✓ | ✓ | ✓ | Next |
| 7.0 | `7.0.33-lts1` | ✓ | ✓ | ✓ | Expansion |
| 7.1 | `7.1.33-lts1` | ✓ | ✓ | ✓ | Expansion |
| 7.2 | `7.2.34-lts1` | ✓ | ✓ | ✓ | Expansion |
| 7.3 | `7.3.33-lts1` | ✓ | ✓ | ✓ | Expansion |
| 7.4 | `7.4.33-lts1` | ✓ | ✓ | ✓ | Expansion |
| 8.1 | `8.1.34-lts1` | ✓ | ✓ | ✓ | Expansion |

Total: **27 configurations** (nine branches × three variants). Aliases do not
represent additional builds.

## Runtime conventions

| Setting | CLI | FPM | Apache |
| --- | --- | --- | --- |
| Primary process | `php` | `php-fpm`, foreground | Apache, foreground |
| HTTP server included | No | No; external FastCGI proxy required | Yes |
| PHP installation prefix | `/usr/local` | `/usr/local` | `/usr/local` |
| Development and production INI templates | Both | Both | Both |
| `docker-php-*` helpers | Planned | Planned | Planned |
| Session upload progress | Enabled; configurable | Enabled; configurable | Enabled; configurable |
| Security patch set | Published LTS 1 set | Published LTS 1 set | Published LTS 1 set |

Builds must download the published LTS 1 source tarball and verify a pinned
SHA-256 digest. Do not reapply patches to already-patched release sources.
CVE-2026-115560 experimental candidates remain excluded.

Provide `PHP_INI_DIR`, extension build/enable helpers, and OCI metadata linking
the package to the source repository. Use a useful, branch-appropriate extension
set rather than copying the test images' `--disable-all` configuration.
PHP 5.4 has no bundled OPcache; later branches have bundled OPcache, with its
build and activation policy still to be finalized.

### Decisions required before publishing

These are not yet implemented or verified:

- Exact bundled extension list for each branch, including compatibility with
  Bookworm libraries and any explicitly unavailable extensions.
- Default active INI configuration and production overrides.
- Exact helper compatibility and required extension-build dependencies.
- FPM pool configuration, Apache configuration, permissions, and signal handling.
- Base-image digest pinning and rebuild policy for Debian security updates.

Record these decisions here as the pilot establishes tested configurations;
do not imply parity with current Docker Official PHP Images without testing it.

## Tags

For each source version `V`, branch `B`, and variant `S` (`cli`, `fpm`, `apache`):

- Versioned: `V-S-bookworm`, `V-S`
- Branch aliases: `B-S-bookworm`, `B-S`
- Additional CLI alias: `B`

PHP 5.4 example (all tags prefixed by `ghcr.io/centillex-labs/php:`):

| Variant | Versioned Bookworm tag | Aliases |
| --- | --- | --- |
| CLI | `5.4.45-lts1-cli-bookworm` | `5.4.45-lts1-cli`, `5.4-cli-bookworm`, `5.4-cli`, `5.4` |
| FPM | `5.4.45-lts1-fpm-bookworm` | `5.4.45-lts1-fpm`, `5.4-fpm-bookworm`, `5.4-fpm` |
| Apache | `5.4.45-lts1-apache-bookworm` | `5.4.45-lts1-apache`, `5.4-apache-bookworm`, `5.4-apache` |

Branch aliases advance with new LTS releases. Image digests identify exact builds;
source-version tags alone must not be treated as digest-level reproducibility
because base packages may receive updates. Never publish a bare `latest` tag.

## Rollout and release gates

1. Implement and validate PHP 5.4 CLI, FPM, and Apache as the pilot.
2. Extend to PHP 5.5 and 5.6, then PHP 7.0–7.4 and 8.1.
3. Add a separate manual-dispatch publishing workflow with `packages: write`.
   Publish only configurations that pass their gates.
4. Make the GHCR package public and link it to `centillex-labs/es-php`.
5. Add usage instructions and published digests to the collective LTS 1 release
   notes. Do not create per-version source git tags or commit source tarballs.

Required gates:

- Verify `PHP_VERSION` has the expected `-lts1` suffix and `PHP_VERSION_ID`
  remains unchanged; verify source digest and release patch manifest.
- Verify expected extensions, INI paths/templates, and extension helper behavior.
- Verify upload progress is enabled by default and remains configurable.
- Exercise FPM FastCGI requests, sessions, worker reuse, and OOM worker replacement.
- Exercise Apache uploads and patched OOM behavior.
- Run the progress-encoding-scope regression against production runtimes.
- Retain an unpatched negative control for security regression tests; exploit
  success markers must be computed, not merely reflected payload strings.
- Record actual test results and limitations before describing an image as ready.

Build and test PHP in Docker only. Keep heavy build work outside Dropbox and run
long builds detached. Production publishing must not include debug or sanitizer
images. These targeted backports do not make EOL PHP fully supported or guarantee
complete exploit resistance.

## Deferred targets

ARM64, Alpine, ZTS, standalone CGI, and debug/sanitizer runtime variants are not
part of the initial production matrix. Each requires separate implementation and
verification before being added.
